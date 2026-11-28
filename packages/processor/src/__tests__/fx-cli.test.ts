import fs, {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { FileRecord } from "@deepsec/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  buildFxAskArgs,
  buildFxSettings,
  FX_DEFAULT_MODEL,
  FX_READ_ONLY_PERMISSIONS,
  FxAgentPlugin,
  findSymlinksOutsideProject,
  fxCostLimitError,
  parseGatewayPricing,
  resetFxPricingCache,
  runFxSetupTask,
} from "../agents/fx-cli.js";
import { ContentFilteredError } from "../agents/shared.js";
import type { AgentProgress, InvestigateOutput } from "../agents/types.js";

vi.mock("../agents/shared.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../agents/shared.js")>();
  return { ...actual, backoff: async () => {} };
});

// AI Gateway's public price list, stubbed so cost estimates never use the network.
const SOL = { input: "0.000002", output: "0.00001", input_cache_read: "0.0000002" };
const GATEWAY_PRICES = {
  data: [
    { id: "openai/gpt-6.2-sol", pricing: SOL },
    { id: "openai/gpt-6.1-sol", pricing: SOL },
  ],
};

beforeEach(() => {
  resetFxPricingCache();
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response(JSON.stringify(GATEWAY_PRICES), { status: 200 })),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function record(filePath: string): FileRecord {
  return {
    filePath,
    projectId: "test",
    candidates: [{ vulnSlug: "xss", lineNumbers: [1], snippet: "code", matchedPattern: "test" }],
    lastScannedAt: "2026-11-19T00:00:00Z",
    lastScannedRunId: "run1",
    fileHash: "abc",
    findings: [],
    analysisHistory: [],
    status: "pending",
  } as FileRecord;
}

async function drain<T>(gen: AsyncGenerator<AgentProgress, T>): Promise<T> {
  let next = await gen.next();
  while (!next.done) next = await gen.next();
  return next.value;
}

describe("fx settings and arguments", () => {
  it("allows only the read, glob and grep tools", () => {
    const settings = buildFxSettings({});
    expect(settings.permission_mode).toBe("ask");
    expect(settings.permission).toEqual(FX_READ_ONLY_PERMISSIONS);
    const projectOnly = { "*": "allow", "/*": "deny", "~*": "deny", "..*": "deny", "*..*": "deny" };
    expect(FX_READ_ONLY_PERMISSIONS).toEqual({
      "*": "deny",
      read: projectOnly,
      glob: projectOnly,
      grep: projectOnly,
    });
    // "*" can't deny web_fetch (its rules only match exact domains); toolbox, denied by "*", hides it.
    expect(settings.tool_placement).toEqual({ web_fetch: "toolbox", web_search: "toolbox" });
    expect(settings.session_titles).toBe(false);
    expect(settings.providers).toBeUndefined();
  });

  it("reads base per-token prices from AI Gateway's model list", () => {
    const rates = parseGatewayPricing({
      data: [
        {
          id: "a/full",
          pricing: {
            input: "0.000002",
            output: "0.00001",
            input_cache_read: "0.0000002",
            input_cache_write: "0.0000025",
          },
        },
        { id: "a/no-cache", pricing: { input: "0.000001", output: "0.000004" } },
        { id: "a/unpriced" },
        { id: "a/blank", pricing: { input: null, output: " " } },
      ],
    });
    expect(rates.get("a/full")).toEqual({
      input: 0.000002,
      output: 0.00001,
      cacheRead: 0.0000002,
      cacheWrite: 0.0000025,
    });
    expect(rates.get("a/no-cache")).toEqual({
      input: 0.000001,
      output: 0.000004,
      cacheRead: 0.000001,
      cacheWrite: 0.000001,
    });
    expect(rates.has("a/unpriced")).toBe(false);
    expect(rates.has("a/blank")).toBe(false);
  });

  it("uses AI Gateway, the default model and the requested effort", () => {
    expect(buildFxAskArgs({ thinkingLevel: "medium" }, { maxTurns: 50 })).toEqual([
      "ask",
      "--json",
      "--ask",
      "--provider",
      "gateway",
      "--model",
      FX_DEFAULT_MODEL,
      "--effort",
      "medium",
      "--config",
      "max_agent_steps=50",
    ]);
    const resumed = buildFxAskArgs(
      { model: "openai/gpt-6.2-sol" },
      { maxTurns: 8, resumeSessionId: "s1" },
    );
    expect(resumed.slice(-2)).toEqual(["--resume", "s1"]);
    // Like the other backends, no thinking level means full effort.
    expect(resumed[resumed.indexOf("--effort") + 1]).toBe("xhigh");
  });
});

describe("FxAgentPlugin.investigate", () => {
  let dir: string;
  let log: string;
  let previousBin: string | undefined;

  beforeEach(() => {
    dir = mkdtempSync(path.join(tmpdir(), "deepsec-fx-test-"));
    log = path.join(dir, "calls.jsonl");
    // A fake `fx`: records each call, answers the investigation with one
    // finding and every follow-up with a refusal report.
    const fake = path.join(dir, "fx");
    writeFileSync(
      fake,
      `#!/usr/bin/env node
const fs = require("node:fs");
const stdin = fs.readFileSync(0, "utf8");
const args = process.argv.slice(2);
const settings = JSON.parse(fs.readFileSync(process.env.HOME + "/.fx/settings.json", "utf8"));
fs.appendFileSync(${JSON.stringify(log)}, JSON.stringify({ args, settings, cwd: process.cwd(), followUp: args.includes("--resume"), mentionsFile: stdin.includes("src/app.ts"), headerEnv: process.env.DEEPSEC_FX_HEADER_0, hasGatewayKey: Boolean(process.env.AI_GATEWAY_API_KEY), hasRouterKey: Boolean(process.env.FX_TEST_ROUTER_KEY), credentialEnv: process.env.DEEPSEC_FX_CREDENTIAL }) + "\\n");
const finding = { severity: "HIGH", vulnSlug: "xss", title: "Unescaped output", description: "d", lineNumbers: [1], recommendation: "r", confidence: "high" };
const answer = args.includes("--resume")
  ? JSON.stringify({ refused: false, skipped: [] })
  : JSON.stringify([{ filePath: "src/app.ts", findings: [finding] }]);
process.stdout.write(JSON.stringify({ exit_code: 0, final_output: answer, session_id: "sess-1", steps: 3,
  usage: { input_tokens: 1200, output_tokens: 300, cache_read_tokens: 900 }, tool_calls: [{ name: "read_file", status: "success" }] }));
`,
    );
    chmodSync(fake, 0o755);
    previousBin = process.env.DEEPSEC_FX_BIN;
    process.env.DEEPSEC_FX_BIN = fake;
  });

  afterEach(() => {
    if (previousBin === undefined) delete process.env.DEEPSEC_FX_BIN;
    else process.env.DEEPSEC_FX_BIN = previousBin;
    rmSync(dir, { recursive: true, force: true });
  });

  it("returns parsed findings with fx usage and continues the same session", async () => {
    const out: InvestigateOutput = await drain(
      new FxAgentPlugin().investigate({
        batch: [record("src/app.ts")],
        projectRoot: dir,
        promptTemplate: "Find vulnerabilities.",
        projectInfo: "",
        config: { model: "openai/gpt-6.2-sol", thinkingLevel: "medium" },
      }),
    );
    expect(out.results).toHaveLength(1);
    expect(out.results[0].findings[0]).toMatchObject({
      title: "Unescaped output",
      severity: "HIGH",
    });
    // Main call plus refusal follow-up, each 1200 input (900 cached) and 300
    // output. fx's input_tokens includes cache reads; inputTokens is uncached.
    expect(out.meta.usage).toEqual({
      inputTokens: 600,
      outputTokens: 600,
      cacheReadInputTokens: 1800,
      cacheCreationInputTokens: 0,
    });
    expect(out.meta.costUsd).toBeCloseTo(600 * 0.000002 + 600 * 0.00001 + 1800 * 0.0000002, 10);
    expect(out.meta).not.toHaveProperty("numTurns");
    expect(out.meta.agentSessionId).toBe("sess-1");
    expect(out.meta.refusal?.refused).toBe(false);

    const calls = readFileSync(log, "utf8")
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));
    expect(calls).toHaveLength(2);
    expect(calls[0]).toMatchObject({ followUp: false, mentionsFile: true });
    expect(calls[0].args).toEqual(
      expect.arrayContaining(["--provider", "gateway", "--effort", "medium"]),
    );
    expect(calls[0].settings.permission).toEqual(FX_READ_ONLY_PERMISSIONS);
    expect(calls[1].args.slice(-2)).toEqual(["--resume", "sess-1"]);
  });

  it("does not let a custom credential name replace the isolated HOME", async () => {
    vi.stubEnv("HOME", "synthetic-host-home");
    vi.stubEnv("AI_GATEWAY_API_KEY", "unrelated-gateway-key");
    try {
      await runFxSetupTask({
        projectRoot: dir,
        prompt: "test",
        config: { aiBaseUrl: "https://router.example/v1", aiApiKeyEnv: "HOME" },
      });
      // The fake child reads the settings from its HOME before writing the log.
      const call = JSON.parse(readFileSync(log, "utf8").trim());
      expect(call.credentialEnv).toBe("synthetic-host-home");
      expect(call.hasGatewayKey).toBe(false);
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it("passes custom endpoint header values to fx through private variables and reports no cost", async () => {
    process.env.FX_TEST_ROUTER_KEY = "sekret";
    try {
      const out: InvestigateOutput = await drain(
        new FxAgentPlugin().investigate({
          batch: [record("src/app.ts")],
          projectRoot: dir,
          promptTemplate: "Find vulnerabilities.",
          projectInfo: "",
          config: {
            model: "router/model",
            aiBaseUrl: "https://router.example/v1",
            aiApiKeyEnv: "FX_TEST_ROUTER_KEY",
            aiCredentialHeader: { name: "x-router-key", scheme: "bearer" },
            aiHeaders: { "X-Org-Id": "acme" },
          },
        }),
      );
      const first = JSON.parse(readFileSync(log, "utf8").trim().split("\n")[0]);
      expect(first.hasRouterKey).toBe(false);
      expect(first.headerEnv).toBe("acme");
      expect(first.credentialEnv).toBe("Bearer sekret");
      expect(first.settings.providers["deepsec-custom"].headers).toEqual({
        "X-Org-Id": { env: "DEEPSEC_FX_HEADER_0" },
        "x-router-key": { env: "DEEPSEC_FX_CREDENTIAL" },
      });
      // Without listed levels fx would drop --effort on the custom endpoint.
      expect(
        first.settings.providers["deepsec-custom"].model_metadata["router/model"].reasoning_efforts
          .xhigh,
      ).toEqual({ reasoning_effort: "xhigh" });
      expect(out.meta.costUsd).toBeUndefined();
      expect(fetch).not.toHaveBeenCalled();
    } finally {
      delete process.env.FX_TEST_ROUTER_KEY;
    }
  });
});

describe("FxAgentPlugin.investigate with incomplete turns", () => {
  const FLAGGED =
    "This content was flagged for possible cybersecurity risk. If this seems wrong, try rephrasing your request.";
  let dir: string;
  let log: string;
  let previousBin: string | undefined;

  const INTERRUPTED = "the turn ended before the model finished";

  // A fake `fx` whose first `failures` main calls end incomplete: exit 1
  // with a JSON result whose output is a progress note that mentions "[]".
  // Later calls answer normally.
  function installFake(failures: number, error = INTERRUPTED) {
    const fake = path.join(dir, "fx");
    writeFileSync(
      fake,
      `#!/usr/bin/env node
const fs = require("node:fs");
fs.readFileSync(0, "utf8");
const args = process.argv.slice(2);
const followUp = args.includes("--resume");
fs.appendFileSync(${JSON.stringify(log)}, JSON.stringify({ followUp, home: process.env.HOME }) + "\\n");
const mainCalls = fs.readFileSync(${JSON.stringify(log)}, "utf8").trim().split("\\n").map(JSON.parse).filter((c) => !c.followUp).length;
if (!followUp && mainCalls <= ${failures}) {
  process.stdout.write(JSON.stringify({ exit_code: 1, error: ${JSON.stringify(error)}, output: "Checked the allowlist; it is [] so far.", session_id: "sess-flagged", usage: { input_tokens: 100, output_tokens: 10 } }));
  process.exit(1);
}
const answer = followUp
  ? JSON.stringify({ refused: false, skipped: [] })
  : JSON.stringify([{ filePath: "src/app.ts", findings: [{ severity: "HIGH", vulnSlug: "xss", title: "Unescaped output", description: "d", lineNumbers: [1], recommendation: "r", confidence: "high" }] }]);
process.stdout.write(JSON.stringify({ exit_code: 0, final_output: answer, session_id: "sess-ok", steps: 2, usage: { input_tokens: 1000, output_tokens: 200, cache_read_tokens: 400 } }));
`,
    );
    chmodSync(fake, 0o755);
    process.env.DEEPSEC_FX_BIN = fake;
  }

  function calls(): Array<{ followUp: boolean; home: string }> {
    return readFileSync(log, "utf8")
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));
  }

  function investigate() {
    return new FxAgentPlugin().investigate({
      batch: [record("src/app.ts")],
      projectRoot: dir,
      promptTemplate: "Find vulnerabilities.",
      projectInfo: "",
      config: { model: "openai/gpt-6.1-sol", thinkingLevel: "medium" },
    });
  }

  beforeEach(() => {
    dir = mkdtempSync(path.join(tmpdir(), "deepsec-fx-incomplete-"));
    log = path.join(dir, "calls.jsonl");
    previousBin = process.env.DEEPSEC_FX_BIN;
  });

  afterEach(() => {
    if (previousBin === undefined) delete process.env.DEEPSEC_FX_BIN;
    else process.env.DEEPSEC_FX_BIN = previousBin;
    rmSync(dir, { recursive: true, force: true });
  });

  it("retries an incomplete turn on a fresh session and ignores its partial output", async () => {
    installFake(1);
    const out: InvestigateOutput = await drain(investigate());
    expect(out.results).toHaveLength(1);
    expect(out.results[0].findings[0]).toMatchObject({ title: "Unescaped output" });
    expect(out.meta.agentSessionId).toBe("sess-ok");
    const main = calls().filter((c) => !c.followUp);
    expect(main).toHaveLength(2);
    expect(main[0].home).not.toBe(main[1].home);
    // The blocked attempt's usage counts too: 100 + 1000 + 1000 (follow-up)
    // input with 800 cached, and 10 + 200 + 200 output.
    expect(out.meta.usage).toEqual({
      inputTokens: 1300,
      outputTokens: 410,
      cacheReadInputTokens: 800,
      cacheCreationInputTokens: 0,
    });
    expect(out.meta.costUsd).toBeCloseTo(1300 * 0.000002 + 410 * 0.00001 + 800 * 0.0000002, 10);
  });

  it("hands a content-filter block to the processor instead of retrying the batch", async () => {
    installFake(99, FLAGGED);
    await expect(drain(investigate())).rejects.toBeInstanceOf(ContentFilteredError);
    expect(calls().filter((c) => !c.followUp)).toHaveLength(1);
  });

  it("fails the batch after the last attempt instead of recording the files as clean", async () => {
    installFake(99);
    await expect(drain(investigate())).rejects.toThrow(
      /fx produced no investigation result after 3 attempt\(s\)\. Last error: fx exited 1: the turn ended before the model finished/,
    );
    const all = calls();
    expect(all.filter((c) => !c.followUp)).toHaveLength(3);
    expect(all.some((c) => c.followUp)).toBe(false);
  });
});

describe("fx backend symlink boundary", () => {
  let dir: string;
  let project: string;
  let previousBin: string | undefined;
  let marker: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(tmpdir(), "deepsec-fx-links-"));
    project = path.join(dir, "project");
    mkdirSync(path.join(project, "src"), { recursive: true });
    mkdirSync(path.join(project, ".git"));
    mkdirSync(path.join(dir, "outside"));
    writeFileSync(path.join(project, "src", "app.ts"), "export {};\n");
    writeFileSync(path.join(dir, "outside", "secret.txt"), "secret\n");
    symlinkSync("app.ts", path.join(project, "src", "alias.ts"));
    symlinkSync("missing.ts", path.join(project, "src", "dangling.ts"));
    symlinkSync("../../outside", path.join(project, ".git", "ignored"));
    marker = path.join(dir, "fx-was-called");
    const fake = path.join(dir, "fx");
    writeFileSync(
      fake,
      `#!/usr/bin/env node\nrequire("node:fs").writeFileSync(${JSON.stringify(marker)}, "1");\n`,
    );
    chmodSync(fake, 0o755);
    previousBin = process.env.DEEPSEC_FX_BIN;
    process.env.DEEPSEC_FX_BIN = fake;
  });

  afterEach(() => {
    if (previousBin === undefined) delete process.env.DEEPSEC_FX_BIN;
    else process.env.DEEPSEC_FX_BIN = previousBin;
    rmSync(dir, { recursive: true, force: true });
  });

  it("refuses to run fx when a link resolves outside the project", async () => {
    symlinkSync("../../outside/secret.txt", path.join(project, "src", "config.ts"));
    expect(findSymlinksOutsideProject(project)).toEqual([path.join("src", "config.ts")]);
    await expect(
      drain(
        new FxAgentPlugin().investigate({
          batch: [record("src/app.ts")],
          projectRoot: project,
          promptTemplate: "Find vulnerabilities.",
          projectInfo: "",
          config: { model: "openai/gpt-6.2-sol" },
        }),
      ),
    ).rejects.toThrow(/symlinks that point outside the project root: src\/config\.ts/);
    expect(() => readFileSync(marker)).toThrow();
  });

  it("walks a clean project once per process, not once per batch", async () => {
    const walk = vi.spyOn(fs, "readdirSync");
    const batch = () =>
      drain(
        new FxAgentPlugin().investigate({
          batch: [record("src/app.ts")],
          projectRoot: project,
          promptTemplate: "Find vulnerabilities.",
          projectInfo: "",
          config: { model: "openai/gpt-6.2-sol" },
        }),
      ).catch(() => undefined);
    try {
      await batch();
      await batch();
      const root = fs.realpathSync.native(project);
      expect(walk.mock.calls.filter(([dir]) => dir === root)).toHaveLength(1);
    } finally {
      walk.mockRestore();
    }
  });
});

describe("fxCostLimitError", () => {
  it("allows a cost limit only when fx can price the model", async () => {
    expect(await fxCostLimitError("openai/gpt-6.1-sol", undefined)).toBeUndefined();
    expect(await fxCostLimitError("acme/unpriced", undefined)).toMatch(/can't be enforced/);
    expect(await fxCostLimitError("openai/gpt-6.1-sol", "https://llm.example.com/v1")).toMatch(
      /custom endpoint/,
    );
  });
});

/** A fake `fx` answering from a script that sees stdin and args. */
function fakeFx(dir: string, body: string): string {
  const fake = path.join(dir, "fx");
  writeFileSync(
    fake,
    `#!/usr/bin/env node
const fs = require("node:fs");
const stdin = fs.readFileSync(0, "utf8");
const args = process.argv.slice(2);
const reply = (finalOutput, extra = {}) => process.stdout.write(JSON.stringify({ exit_code: 0, final_output: finalOutput, session_id: "sess", steps: 1, usage: { input_tokens: 100, output_tokens: 10 }, ...extra }));
${body}
`,
  );
  chmodSync(fake, 0o755);
  return fake;
}

describe("FxAgentPlugin with a scripted fx", () => {
  let dir: string;
  let previousBin: string | undefined;

  beforeEach(() => {
    dir = mkdtempSync(path.join(tmpdir(), "deepsec-fx-scripted-"));
    previousBin = process.env.DEEPSEC_FX_BIN;
  });

  afterEach(() => {
    if (previousBin === undefined) delete process.env.DEEPSEC_FX_BIN;
    else process.env.DEEPSEC_FX_BIN = previousBin;
    rmSync(dir, { recursive: true, force: true });
  });

  it("fails a batch whose fx result has no token counts", async () => {
    process.env.DEEPSEC_FX_BIN = fakeFx(dir, `reply("[]", { usage: {} });`);
    await expect(
      drain(
        new FxAgentPlugin().investigate({
          batch: [record("src/app.ts")],
          projectRoot: dir,
          promptTemplate: "Find vulnerabilities.",
          projectInfo: "",
          config: { model: "openai/gpt-6.2-sol" },
        }),
      ),
    ).rejects.toThrow("fx --json output has no usage");
  });

  it("fails a batch whose follow-up has no token counts", async () => {
    process.env.DEEPSEC_FX_BIN = fakeFx(
      dir,
      `if (args.includes("--resume")) reply(JSON.stringify({ refused: false, skipped: [] }), { usage: {} });
else reply(JSON.stringify([{ filePath: "src/app.ts", findings: [] }]));`,
    );
    await expect(
      drain(
        new FxAgentPlugin().investigate({
          batch: [record("src/app.ts")],
          projectRoot: dir,
          promptTemplate: "Find vulnerabilities.",
          projectInfo: "",
          config: { model: "openai/gpt-6.2-sol" },
        }),
      ),
    ).rejects.toThrow("fx --json output has no usage");
  });

  it("stops on exhausted quota in a follow-up", async () => {
    process.env.DEEPSEC_FX_BIN = fakeFx(
      dir,
      `if (args.includes("--resume")) {
  process.stdout.write(JSON.stringify({ exit_code: 1, error: "Insufficient funds. Please add credits to your account", usage: { input_tokens: 1, output_tokens: 0 } }));
  process.exit(1);
}
reply(JSON.stringify([{ filePath: "src/app.ts", findings: [] }]));`,
    );
    await expect(
      drain(
        new FxAgentPlugin().investigate({
          batch: [record("src/app.ts")],
          projectRoot: dir,
          promptTemplate: "Find vulnerabilities.",
          projectInfo: "",
          config: { model: "openai/gpt-6.2-sol" },
        }),
      ),
    ).rejects.toMatchObject({ name: "QuotaExhaustedError" });
  });

  it("repairs non-JSON revalidation output in the same session", async () => {
    process.env.DEEPSEC_FX_BIN = fakeFx(
      dir,
      `if (!args.includes("--resume")) reply("The finding looks real.");
else if (stdin.includes("declined to fully analyze")) reply(JSON.stringify({ refused: false, skipped: [] }));
else reply(JSON.stringify([{ findingId: "finding_1", verdict: "true-positive", reasoning: "Output is unescaped." }]));`,
    );
    const rec = record("src/app.ts");
    rec.findings = [
      {
        findingId: "finding_1",
        severity: "HIGH",
        vulnSlug: "xss",
        title: "Unescaped output",
        description: "d",
        lineNumbers: [1],
        recommendation: "r",
        confidence: "high",
      },
    ];
    const out = await drain(
      new FxAgentPlugin().revalidate({
        batch: [rec],
        projectRoot: dir,
        projectInfo: "",
        config: { model: "openai/gpt-6.1-sol" },
      }),
    );
    expect(out.verdicts).toEqual([
      expect.objectContaining({ findingId: "finding_1", verdict: "true-positive" }),
    ]);
    expect(out.rawResponses?.map((r) => r.kind)).toContain("json-repair");
    expect(out.meta.costUsd).toBeGreaterThan(0);
  });
});

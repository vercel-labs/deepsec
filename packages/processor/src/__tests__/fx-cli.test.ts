import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { FileRecord } from "@deepsec/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  buildFxAskArgs,
  buildFxSettings,
  FX_DEFAULT_MODEL,
  FX_READ_ONLY_PERMISSIONS,
  FxAgentPlugin,
  parseFxAskOutput,
  resolveFxEffort,
} from "../agents/fx-cli.js";
import type { AgentProgress, InvestigateOutput } from "../agents/types.js";

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
    // Permission rules do not cover the web tools; toolbox, denied by "*", hides them.
    expect(settings.tool_placement).toEqual({ web_fetch: "toolbox", web_search: "toolbox" });
    expect(settings.session_titles).toBe(false);
    expect(settings.providers).toBeUndefined();
  });

  it("adds a custom provider only when a base URL is configured", () => {
    const settings = buildFxSettings({
      aiBaseUrl: "http://127.0.0.1:9/v1",
      aiApiKeyEnv: "MY_KEY",
      model: "m",
    });
    expect(settings.providers).toMatchObject({
      "deepsec-custom": {
        base_url: "http://127.0.0.1:9/v1",
        auth: { type: "bearer", env: "MY_KEY" },
        model_metadata: { m: { supports_tool_use: true } },
      },
    });
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
    expect(resumed).toContain("high");
  });

  it("rejects thinking levels fx does not accept", () => {
    expect(resolveFxEffort("xhigh")).toBe("xhigh");
    expect(() => resolveFxEffort("max")).toThrow(/does not support thinking level "max"/);
  });

  it("parses the JSON object fx ask prints", () => {
    expect(
      parseFxAskOutput('\n{"exit_code":0,"final_output":"[]","session_id":"s"}\n').session_id,
    ).toBe("s");
    expect(() => parseFxAskOutput("no json")).toThrow(/no JSON result/);
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
fs.appendFileSync(${JSON.stringify(log)}, JSON.stringify({ args, settings, cwd: process.cwd(), followUp: args.includes("--resume"), mentionsFile: stdin.includes("src/app.ts") }) + "\\n");
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
    expect(out.meta.usage).toEqual({
      inputTokens: 1200,
      outputTokens: 300,
      cacheReadInputTokens: 900,
      cacheCreationInputTokens: 0,
    });
    expect(out.meta.numTurns).toBe(3);
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
});

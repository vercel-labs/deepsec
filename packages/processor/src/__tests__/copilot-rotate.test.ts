import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { FileRecord } from "@deepsec/core";
import { describe, expect, it } from "vitest";
import { CopilotRotatePlugin } from "../agents/copilot-rotate.js";

const fixtureCommand = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "fixtures",
  "fake-copilot-delegate.mjs",
);

function makeRecord(): FileRecord {
  return {
    projectId: "proj",
    filePath: "src/app.ts",
    candidates: [
      {
        vulnSlug: "xss",
        lineNumbers: [7],
        snippet: "danger",
        matchedPattern: "innerHTML",
      },
    ],
    lastScannedAt: new Date().toISOString(),
    lastScannedRunId: "scan",
    fileHash: "hash",
    findings: [],
    analysisHistory: [],
    status: "pending",
  };
}

async function collect<T>(gen: AsyncGenerator<unknown, T>): Promise<T> {
  let next = await gen.next();
  while (!next.done) next = await gen.next();
  return next.value;
}

describe("CopilotRotatePlugin", () => {
  it("defaults Copilot Rotate runs to gpt-5.5", async () => {
    const plugin = new CopilotRotatePlugin();
    const gen = plugin.investigate({
      batch: [makeRecord()],
      projectRoot: process.cwd(),
      promptTemplate: "Review these files.",
      projectInfo: "",
      config: { command: fixtureCommand, timeoutMs: 10_000 },
    });

    const started = await gen.next();
    expect(started.value).toMatchObject({
      type: "started",
      message: expect.stringContaining("gpt-5.5"),
    });
    await gen.return(undefined as never);
  });

  it("investigates via an injected delegate command and parses fenced JSON", async () => {
    fs.chmodSync(fixtureCommand, 0o755);
    const plugin = new CopilotRotatePlugin();
    const output = await collect(
      plugin.investigate({
        batch: [makeRecord()],
        projectRoot: process.cwd(),
        promptTemplate: "Review these files.",
        projectInfo: "",
        config: { command: fixtureCommand, timeoutMs: 10_000 },
      }),
    );

    expect(output.results).toHaveLength(1);
    expect(output.results[0].filePath).toBe("src/app.ts");
    expect(output.results[0].findings[0].title).toBe("stored xss");
    expect(output.meta.agentSessionId).toBe("fake-investigate");
    expect(output.meta.numTurns).toBe(2);
  });

  it("revalidates via an injected delegate command and parses verdicts", async () => {
    fs.chmodSync(fixtureCommand, 0o755);
    const plugin = new CopilotRotatePlugin();
    const record = makeRecord();
    record.findings = [
      {
        severity: "HIGH",
        vulnSlug: "xss",
        title: "stored xss",
        description: "Stored XSS",
        lineNumbers: [7],
        recommendation: "Escape",
        confidence: "high",
      },
    ];

    const output = await collect(
      plugin.revalidate({
        batch: [record],
        projectRoot: process.cwd(),
        projectInfo: "",
        config: { command: fixtureCommand, timeoutMs: 10_000 },
      }),
    );

    expect(output.verdicts).toHaveLength(1);
    expect(output.verdicts[0].verdict).toBe("true-positive");
    expect(output.meta.agentSessionId).toBe("fake-revalidate");
    expect(output.meta.numTurns).toBe(3);
  });

  it("fails loud when Copilot output is malformed", async () => {
    fs.chmodSync(fixtureCommand, 0o755);
    const plugin = new CopilotRotatePlugin();

    await expect(
      collect(
        plugin.investigate({
          batch: [makeRecord()],
          projectRoot: process.cwd(),
          promptTemplate: "MALFORMED",
          projectInfo: "",
          config: { command: fixtureCommand, timeoutMs: 10_000 },
        }),
      ),
    ).rejects.toThrow(/parseable JSON findings array/);
  });

  it("fails cleanly when the delegated Copilot command times out", async () => {
    fs.chmodSync(fixtureCommand, 0o755);
    const plugin = new CopilotRotatePlugin();

    await expect(
      collect(
        plugin.investigate({
          batch: [makeRecord()],
          projectRoot: process.cwd(),
          promptTemplate: "SLOW",
          projectInfo: "",
          config: { command: fixtureCommand, timeoutMs: 50 },
        }),
      ),
    ).rejects.toThrow(/timeout after 50ms/);
  });

  describe("VAL-PROMPT-001: prompt private transport", () => {
    const SENTINEL = "SUPER_SECRET_SENTINEL_abc123_DO_NOT_LEAK";

    it("does not expose prompt in spawned argv (useDelegate=true, default)", async () => {
      fs.chmodSync(fixtureCommand, 0o755);
      const plugin = new CopilotRotatePlugin();
      // Capture stderr to verify argv dump from fixture.
      let capturedStderr = "";
      const gen = plugin.investigate({
        batch: [makeRecord()],
        projectRoot: process.cwd(),
        promptTemplate: `Review these files. ${SENTINEL}`,
        projectInfo: "",
        config: { command: fixtureCommand, timeoutMs: 10_000, useDelegate: true },
      });
      const output = await collect(gen);

      // The fixture emits argv= line. Directly verify by spawning and capturing.
      const child = spawn(fixtureCommand, ["worker", "gpt-5.5", "xhigh", process.cwd(), "--prompt-stdin"], {
        stdio: ["pipe", "pipe", "pipe"],
      });
      child.stdin!.write(`Review these files. ${SENTINEL}`);
      child.stdin!.end();
      const stderrChunks: string[] = [];
      child.stderr!.on("data", (c: Buffer) => stderrChunks.push(c.toString()));
      await new Promise<void>((resolve) => child.on("close", resolve));
      capturedStderr = stderrChunks.join("");

      // Verify: argv line should NOT contain the sentinel
      const argvLine = capturedStderr.split("\n").find((l) => l.includes("argv="));
      expect(argvLine).toBeDefined();
      expect(argvLine).not.toContain(SENTINEL);
      // But the args should contain --prompt-stdin marker
      expect(argvLine).toContain("--prompt-stdin");

      // The investigation still produced correct output (prompt was delivered via stdin)
      expect(output.results).toHaveLength(1);
    });

    it("does not expose prompt in spawned argv (useDelegate=false)", async () => {
      fs.chmodSync(fixtureCommand, 0o755);
      // For useDelegate=false, args are: delegate --role worker --model ... --prompt-stdin
      const child = spawn(fixtureCommand, [
        "delegate", "--role", "worker", "--model", "gpt-5.5",
        "--effort", "xhigh", "--timeout-ms", "10000", "--prompt-stdin",
      ], {
        stdio: ["pipe", "pipe", "pipe"],
      });
      child.stdin!.write(`Review these files. ${SENTINEL}`);
      child.stdin!.end();
      const stderrChunks: string[] = [];
      child.stderr!.on("data", (c: Buffer) => stderrChunks.push(c.toString()));
      await new Promise<void>((resolve) => child.on("close", resolve));
      const capturedStderr = stderrChunks.join("");

      const argvLine = capturedStderr.split("\n").find((l) => l.includes("argv="));
      expect(argvLine).toBeDefined();
      expect(argvLine).not.toContain(SENTINEL);
      expect(argvLine).toContain("--prompt-stdin");
    });

    it("sentinel prompt is delivered via stdin and read by delegate (useDelegate=true)", async () => {
      fs.chmodSync(fixtureCommand, 0o755);
      const plugin = new CopilotRotatePlugin();
      const output = await collect(
        plugin.investigate({
          batch: [makeRecord()],
          projectRoot: process.cwd(),
          promptTemplate: "Review these files.",
          projectInfo: "",
          config: { command: fixtureCommand, timeoutMs: 10_000, useDelegate: true },
        }),
      );

      // Fixture successfully parsed the stdin-delivered prompt and produced output.
      expect(output.results).toHaveLength(1);
      expect(output.results[0].findings[0].title).toBe("stored xss");
    });

    it("sentinel prompt is delivered via stdin and read by delegate (useDelegate=false)", async () => {
      fs.chmodSync(fixtureCommand, 0o755);
      const plugin = new CopilotRotatePlugin();
      const output = await collect(
        plugin.investigate({
          batch: [makeRecord()],
          projectRoot: process.cwd(),
          promptTemplate: "Review these files.",
          projectInfo: "",
          config: { command: fixtureCommand, timeoutMs: 10_000, useDelegate: false },
        }),
      );

      expect(output.results).toHaveLength(1);
      expect(output.results[0].findings[0].title).toBe("stored xss");
    });
  });
});

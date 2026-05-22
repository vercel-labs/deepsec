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
});

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createRunMeta, generateRunId, readFileRecord, writeFileRecord } from "../run.js";

let cleanups: Array<() => void> = [];

afterEach(() => {
  for (const cleanup of cleanups.reverse()) cleanup();
  cleanups = [];
  delete process.env.DEEPSEC_DATA_ROOT;
});

describe("generateRunId", () => {
  it("returns a string with timestamp and suffix", () => {
    const id = generateRunId();
    expect(id).toMatch(/^\d{14}-[a-f0-9]{16}$/);
  });

  it("generates unique IDs", () => {
    const ids = new Set(Array.from({ length: 20 }, () => generateRunId()));
    expect(ids.size).toBe(20);
  });
});

describe("createRunMeta", () => {
  it("creates a scan RunMeta", () => {
    const meta = createRunMeta({
      projectId: "test-project",
      rootPath: "/tmp/test",
      type: "scan",
      scannerConfig: { matcherSlugs: ["xss", "rce"] },
    });

    expect(meta.projectId).toBe("test-project");
    expect(meta.type).toBe("scan");
    expect(meta.phase).toBe("running");
    expect(meta.scannerConfig?.matcherSlugs).toEqual(["xss", "rce"]);
    expect(meta.stats).toEqual({});
    expect(meta.runId).toMatch(/^\d{14}-[a-f0-9]{16}$/);
  });

  it("creates a process RunMeta", () => {
    const meta = createRunMeta({
      projectId: "test",
      rootPath: "/tmp",
      type: "process",
      processorConfig: {
        agentType: "claude-agent-sdk",
        model: "claude-opus-4-6",
        modelConfig: {},
      },
    });

    expect(meta.type).toBe("process");
    expect(meta.processorConfig?.agentType).toBe("claude-agent-sdk");
  });
});

describe("writeFileRecord security hygiene", () => {
  it("redacts and caps model-controlled finding fields before persistence", () => {
    const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-core-"));
    process.env.DEEPSEC_DATA_ROOT = dataRoot;
    cleanups.push(() => fs.rmSync(dataRoot, { recursive: true, force: true }));

    writeFileRecord({
      projectId: "p",
      filePath: "src/a.ts",
      candidates: [
        {
          vulnSlug: "xss",
          lineNumbers: [1],
          snippet: 'const apiKey = "sk_live_abcdefghijklmnop";',
          matchedPattern: "x",
        },
      ],
      lastScannedAt: new Date().toISOString(),
      lastScannedRunId: "scan",
      fileHash: "h",
      findings: [
        {
          severity: "HIGH",
          vulnSlug: "xss",
          title: `leak Bearer ${"a".repeat(30)}`,
          description: `secret="${"b".repeat(30)}"\n${"x".repeat(20_000)}`,
          lineNumbers: [1],
          recommendation: `token=${"c".repeat(30)}`,
          confidence: "high",
          revalidation: {
            verdict: "uncertain",
            reasoning: `authorization=${"d".repeat(30)}`,
            revalidatedAt: new Date().toISOString(),
            runId: "rv",
            model: "m",
          },
        },
      ],
      analysisHistory: [
        {
          runId: "process",
          investigatedAt: new Date().toISOString(),
          durationMs: 1,
          agentType: "stub",
          model: "stub",
          modelConfig: {},
          findingCount: 1,
          refusal: {
            refused: true,
            reason: `password=${"e".repeat(30)}`,
            raw: "r".repeat(4_000),
          },
        },
      ],
      status: "analyzed",
    });

    const record = readFileRecord("p", "src/a.ts")!;
    expect(record.findings[0].title).toContain("[redacted: credential-shaped value]");
    expect(record.findings[0].description.length).toBeLessThan(13_000);
    expect(record.findings[0].recommendation).toContain("[redacted: credential-shaped value]");
    expect(record.findings[0].revalidation?.reasoning).toContain(
      "[redacted: credential-shaped value]",
    );
    expect(record.analysisHistory[0].refusal?.raw?.length).toBeLessThan(2_100);
  });

  it("refuses to write through symlinked data directories", () => {
    const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-core-"));
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-core-outside-"));
    process.env.DEEPSEC_DATA_ROOT = dataRoot;
    cleanups.push(() => fs.rmSync(dataRoot, { recursive: true, force: true }));
    cleanups.push(() => fs.rmSync(outside, { recursive: true, force: true }));

    fs.symlinkSync(outside, path.join(dataRoot, "p"));

    expect(() =>
      writeFileRecord({
        projectId: "p",
        filePath: "src/a.ts",
        candidates: [],
        lastScannedAt: new Date().toISOString(),
        lastScannedRunId: "scan",
        fileHash: "h",
        findings: [],
        analysisHistory: [],
        status: "pending",
      }),
    ).toThrow(/symlinked data directory/);
  });
});

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { FileRecord } from "@deepsec/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// triage() drives the Claude Agent SDK's `query` directly (not via the plugin
// agent system), so stub the SDK to yield a canned verdict payload.
const sdk = vi.hoisted(() => ({ resultText: "" }));
vi.mock("@anthropic-ai/claude-agent-sdk", () => ({
  query: () =>
    (async function* () {
      yield { type: "result", subtype: "success", result: sdk.resultText };
    })(),
}));

import { triage } from "../triage.js";

function setupProject(): {
  projectId: string;
  writeRecord: (rec: FileRecord) => void;
  readRecord: (rel: string) => FileRecord;
} {
  const projectId = "triage-test";
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-triage-"));
  const targetRoot = path.join(tmp, "target");
  const dataRoot = path.join(tmp, "data");
  fs.mkdirSync(targetRoot, { recursive: true });
  fs.mkdirSync(path.join(dataRoot, projectId, "files"), { recursive: true });
  fs.writeFileSync(
    path.join(dataRoot, projectId, "project.json"),
    JSON.stringify({ projectId, rootPath: targetRoot, createdAt: new Date().toISOString() }),
  );
  process.env.DEEPSEC_DATA_ROOT = dataRoot;

  const recordPath = (rel: string) => path.join(dataRoot, projectId, "files", `${rel}.json`);
  const writeRecord = (rec: FileRecord): void => {
    const p = recordPath(rec.filePath);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, JSON.stringify(rec));
  };
  const readRecord = (rel: string): FileRecord =>
    JSON.parse(fs.readFileSync(recordPath(rel), "utf-8"));
  return { projectId, writeRecord, readRecord };
}

function recordWithFinding(projectId: string, filePath: string, title: string): FileRecord {
  return {
    filePath,
    projectId,
    candidates: [
      { vulnSlug: "missing-authz", lineNumbers: [1], snippet: "// stub", matchedPattern: "p" },
    ],
    lastScannedAt: new Date().toISOString(),
    lastScannedRunId: "scan-fixture",
    fileHash: "fixture-hash",
    findings: [
      {
        severity: "MEDIUM",
        vulnSlug: "missing-authz",
        title,
        description: "x",
        lineNumbers: [1],
        recommendation: "x",
        confidence: "high",
      },
    ],
    analysisHistory: [],
    status: "analyzed",
  };
}

describe("triage verdict correlation", () => {
  let prevDataRoot: string | undefined;

  beforeEach(() => {
    prevDataRoot = process.env.DEEPSEC_DATA_ROOT;
  });

  afterEach(() => {
    if (prevDataRoot === undefined) delete process.env.DEEPSEC_DATA_ROOT;
    else process.env.DEEPSEC_DATA_ROOT = prevDataRoot;
  });

  it("maps each verdict to its own finding by id when titles collide", async () => {
    const fx = setupProject();
    fx.writeRecord(recordWithFinding(fx.projectId, "a.ts", "Missing authorization check"));
    fx.writeRecord(recordWithFinding(fx.projectId, "b.ts", "Missing authorization check"));

    sdk.resultText = [
      "```json",
      JSON.stringify([
        {
          id: 1,
          title: "Missing authorization check",
          priority: "P0",
          exploitability: "trivial",
          impact: "high",
          reasoning: "one",
        },
        {
          id: 2,
          title: "Missing authorization check",
          priority: "skip",
          exploitability: "difficult",
          impact: "low",
          reasoning: "two",
        },
      ]),
      "```",
    ].join("\n");

    const result = await triage({ projectId: fx.projectId, concurrency: 1 });

    const a = fx.readRecord("a.ts").findings[0];
    const b = fx.readRecord("b.ts").findings[0];

    // Both same-titled findings must be triaged. Before the fix, title-matching
    // collapsed both verdicts onto the first finding, leaving the other one
    // untouched.
    expect(a.triage).toBeDefined();
    expect(b.triage).toBeDefined();

    // And each keeps its own distinct verdict (P0 vs skip), rather than one
    // verdict overwriting the other.
    const priorities = [a.triage?.priority, b.triage?.priority].sort();
    expect(priorities).toEqual(["P0", "skip"]);

    expect(result.triaged).toBe(2);
    expect(result.p0).toBe(1);
    expect(result.skip).toBe(1);
  });
});

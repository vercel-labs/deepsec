import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { FileRecord } from "@deepsec/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// triage() drives the Claude Agent SDK's `query` directly, so stub the SDK to
// yield a canned (here: malformed) result payload.
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
  const projectId = "triage-parse-test";
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-triage-parse-"));
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
    candidates: [{ vulnSlug: "ssrf", lineNumbers: [1], snippet: "// stub", matchedPattern: "p" }],
    lastScannedAt: new Date().toISOString(),
    lastScannedRunId: "scan-fixture",
    fileHash: "fixture-hash",
    findings: [
      {
        severity: "MEDIUM",
        vulnSlug: "ssrf",
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

describe("triage JSON-parse robustness", () => {
  let prevDataRoot: string | undefined;

  beforeEach(() => {
    prevDataRoot = process.env.DEEPSEC_DATA_ROOT;
  });

  afterEach(() => {
    if (prevDataRoot === undefined) delete process.env.DEEPSEC_DATA_ROOT;
    else process.env.DEEPSEC_DATA_ROOT = prevDataRoot;
  });

  it("recovers a trailing-comma verdict array via the tolerant parser", async () => {
    const fx = setupProject();
    fx.writeRecord(recordWithFinding(fx.projectId, "a.ts", "SSRF in fetch"));

    // Trailing comma before the closing brace — invalid strict JSON, but a
    // jsonrepair-class error the tolerant parser recovers. Before the fix a
    // bare JSON.parse threw, was swallowed, and the finding was left untriaged.
    sdk.resultText =
      '```json\n[{"title":"SSRF in fetch","priority":"P0",' +
      '"exploitability":"trivial","impact":"high","reasoning":"r",}]\n```';

    const result = await triage({ projectId: fx.projectId, concurrency: 1 });

    expect(fx.readRecord("a.ts").findings[0].triage?.priority).toBe("P0");
    expect(result.triaged).toBe(1);
  });

  it("surfaces a batch as failed when the output is unparseable, not silently empty", async () => {
    const fx = setupProject();
    fx.writeRecord(recordWithFinding(fx.projectId, "a.ts", "SSRF in fetch"));

    // Prose the model returned instead of JSON. strict JSON.parse rejects it
    // (before the fix, that was swallowed and printed as "0 triaged"), and
    // jsonrepair can only coerce it to a bare string — not an array — so the
    // tolerant parser fails loud.
    sdk.resultText = "I cannot comply with this request";

    const messages: string[] = [];
    const result = await triage({
      projectId: fx.projectId,
      concurrency: 1,
      onProgress: (p) => messages.push(p.message),
    });

    // The batch is reported as failed (before the fix it printed "0 triaged"
    // as a success), and the finding stays untriaged.
    expect(messages.some((m) => /failed/i.test(m))).toBe(true);
    expect(messages.some((m) => /\b0 triaged\b/.test(m))).toBe(false);
    expect(fx.readRecord("a.ts").findings[0].triage).toBeUndefined();
    expect(result.triaged).toBe(0);
  });
});

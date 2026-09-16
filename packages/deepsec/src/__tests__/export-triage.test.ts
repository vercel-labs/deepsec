import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { FileRecord } from "@deepsec/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { exportCommand } from "../commands/export.js";

function makeRecord(overrides: Partial<FileRecord> = {}): FileRecord {
  return {
    filePath: "src/foo.ts",
    projectId: "test-proj",
    candidates: [],
    lastScannedAt: "2026-05-08T00:00:00.000Z",
    lastScannedRunId: "scan1",
    fileHash: "h",
    findings: [
      {
        severity: "HIGH",
        vulnSlug: "xss",
        title: "Reflected XSS in handler",
        description: "User input flows to response without escaping.",
        lineNumbers: [42],
        recommendation: "Escape the value.",
        confidence: "high",
        triage: {
          priority: "P0",
          exploitability: "trivial",
          impact: "high",
          reasoning: "External attacker crafts a malicious URL.",
          triagedAt: "2026-05-08T12:00:00.000Z",
          model: "claude-sonnet-4-6",
        },
      },
    ],
    analysisHistory: [
      {
        runId: "run-1",
        investigatedAt: "2026-05-08T11:00:00.000Z",
        durationMs: 1000,
        agentType: "claude-agent-sdk",
        model: "claude-opus-4-7",
        modelConfig: {},
        findingCount: 1,
      },
    ],
    status: "analyzed",
    ...overrides,
  };
}

let prevDataRoot: string | undefined;
let tmpRoot: string;
let logSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-export-triage-"));
  prevDataRoot = process.env.DEEPSEC_DATA_ROOT;
  process.env.DEEPSEC_DATA_ROOT = tmpRoot;

  const projectId = "test-proj";
  const projectDir = path.join(tmpRoot, projectId);
  fs.mkdirSync(projectDir, { recursive: true });
  fs.writeFileSync(
    path.join(projectDir, "project.json"),
    JSON.stringify({
      projectId,
      rootPath: "/tmp/fake",
      createdAt: "2026-05-08T00:00:00.000Z",
    }),
  );

  const record = makeRecord();
  const recordPath = path.join(projectDir, "files", record.filePath + ".json");
  fs.mkdirSync(path.dirname(recordPath), { recursive: true });
  fs.writeFileSync(recordPath, JSON.stringify(record));

  logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
});

afterEach(() => {
  logSpy.mockRestore();
  fs.rmSync(tmpRoot, { recursive: true, force: true });
  if (prevDataRoot === undefined) delete process.env.DEEPSEC_DATA_ROOT;
  else process.env.DEEPSEC_DATA_ROOT = prevDataRoot;
});

describe("export propagates triage data (issue #64)", () => {
  it("includes metadata.triage in the JSON export", async () => {
    const out = path.join(tmpRoot, "findings.json");
    await exportCommand({ projectId: "test-proj", format: "json", out });

    const data = JSON.parse(fs.readFileSync(out, "utf-8"));
    expect(data).toHaveLength(1);
    expect(data[0].metadata.triage).toEqual({
      priority: "P0",
      exploitability: "trivial",
      impact: "high",
      reasoning: "External attacker crafts a malicious URL.",
      triagedAt: "2026-05-08T12:00:00.000Z",
      model: "claude-sonnet-4-6",
    });
  });

  it("renders triage fields in the md-dir export body", async () => {
    const outDir = path.join(tmpRoot, "md-out");
    await exportCommand({ projectId: "test-proj", format: "md-dir", out: outDir });

    const sevDir = path.join(outDir, "HIGH");
    const files = fs.readdirSync(sevDir).filter((n) => n.endsWith(".md"));
    expect(files).toHaveLength(1);

    const body = fs.readFileSync(path.join(sevDir, files[0]), "utf-8");
    expect(body).toContain("## Triage");
    expect(body).toContain("**Priority:** P0");
    expect(body).toContain("**Exploitability:** trivial");
    expect(body).toContain("**Impact:** high");
    expect(body).toContain("External attacker crafts a malicious URL.");
    expect(body).toContain("2026-05-08T12:00:00.000Z");
    expect(body).toContain("claude-sonnet-4-6");
  });

  it("omits metadata.triage and the Triage section when no triage is present", async () => {
    const projectDir = path.join(tmpRoot, "test-proj");
    const record = makeRecord();
    record.findings[0].triage = undefined;
    fs.writeFileSync(
      path.join(projectDir, "files", record.filePath + ".json"),
      JSON.stringify(record),
    );

    const jsonOut = path.join(tmpRoot, "findings-no-triage.json");
    await exportCommand({ projectId: "test-proj", format: "json", out: jsonOut });
    const data = JSON.parse(fs.readFileSync(jsonOut, "utf-8"));
    expect(data[0].metadata.triage).toBeUndefined();

    const mdOut = path.join(tmpRoot, "md-out-no-triage");
    await exportCommand({ projectId: "test-proj", format: "md-dir", out: mdOut });
    const files = fs.readdirSync(path.join(mdOut, "HIGH")).filter((n) => n.endsWith(".md"));
    const body = fs.readFileSync(path.join(mdOut, "HIGH", files[0]), "utf-8");
    expect(body).not.toContain("## Triage");
  });
});

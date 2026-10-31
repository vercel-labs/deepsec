import { describe, expect, it } from "vitest";
import { fileRecordSchema, runMetaSchema, salvageFileRecord } from "../schemas.js";

describe("fileRecordSchema", () => {
  it("accepts valid file record", () => {
    const valid = {
      filePath: "src/api/users.ts",
      projectId: "test",
      candidates: [
        {
          vulnSlug: "xss",
          lineNumbers: [10, 15],
          snippet: "some code",
          matchedPattern: "dangerouslySetInnerHTML",
        },
      ],
      lastScannedAt: "2026-04-01T14:30:52.000Z",
      lastScannedRunId: "20260401-a1b2",
      fileHash: "abc123",
      findings: [],
      analysisHistory: [],
      status: "pending",
    };
    expect(() => fileRecordSchema.parse(valid)).not.toThrow();
  });

  it("accepts analyzed file record with findings and history", () => {
    const valid = {
      filePath: "src/api/users.ts",
      projectId: "test",
      candidates: [],
      lastScannedAt: "2026-04-01T14:30:52.000Z",
      lastScannedRunId: "run1",
      fileHash: "abc",
      findings: [
        {
          severity: "HIGH",
          vulnSlug: "xss",
          title: "XSS via innerHTML",
          description: "desc",
          lineNumbers: [10],
          recommendation: "fix",
          confidence: "high",
        },
      ],
      analysisHistory: [
        {
          runId: "run1",
          investigatedAt: "2026-04-01T15:00:00.000Z",
          durationMs: 5000,
          agentType: "claude-agent-sdk",
          model: "claude-opus-4-6",
          modelConfig: {},
          findingCount: 1,
        },
      ],
      status: "analyzed",
    };
    expect(() => fileRecordSchema.parse(valid)).not.toThrow();
  });

  it("rejects invalid status", () => {
    const invalid = {
      filePath: "test.ts",
      projectId: "test",
      candidates: [],
      lastScannedAt: "2026-04-01",
      lastScannedRunId: "x",
      fileHash: "x",
      findings: [],
      analysisHistory: [],
      status: "invalid",
    };
    expect(() => fileRecordSchema.parse(invalid)).toThrow();
  });
});

describe("salvageFileRecord", () => {
  const validFinding = {
    severity: "HIGH",
    vulnSlug: "xss",
    title: "XSS via innerHTML",
    description: "desc",
    lineNumbers: [10],
    recommendation: "fix",
    confidence: "high",
  };

  function rawRecord(findings: unknown[]): Record<string, unknown> {
    return {
      filePath: "src/api/users.ts",
      projectId: "test",
      candidates: [],
      lastScannedAt: "2026-04-01T14:30:52.000Z",
      lastScannedRunId: "run1",
      fileHash: "abc",
      findings,
      analysisHistory: [],
      status: "analyzed",
    };
  }

  it("returns the record untouched when fully valid", () => {
    const out = salvageFileRecord(rawRecord([validFinding]));
    expect(out.ok).toBe(true);
    if (out.ok) {
      expect(out.record.findings).toHaveLength(1);
      expect(out.droppedFindings).toEqual([]);
    }
  });

  it("keeps valid findings and reports the malformed ones", () => {
    // One bad finding used to fail the whole record's parse, and the
    // callers' silent catch made the file's valid findings vanish too.
    const out = salvageFileRecord(
      rawRecord([
        validFinding,
        { ...validFinding, title: "bad severity", severity: "INFORMATIONAL" },
        { ...validFinding, title: "bad lines", lineNumbers: ["10"] },
      ]),
    );
    expect(out.ok).toBe(true);
    if (out.ok) {
      expect(out.record.findings.map((f) => f.title)).toEqual(["XSS via innerHTML"]);
      expect(out.droppedFindings).toHaveLength(2);
      expect(out.droppedFindings[0].index).toBe(1);
      expect(out.droppedFindings[0].issues).toContain("severity");
      expect(out.droppedFindings[1].index).toBe(2);
      expect(out.droppedFindings[1].issues).toContain("lineNumbers");
    }
  });

  it("rejects the record when the envelope itself is invalid", () => {
    const out = salvageFileRecord({ ...rawRecord([validFinding]), status: "nope" });
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.error).toContain("status");
  });

  it("rejects non-object input", () => {
    expect(salvageFileRecord("nope").ok).toBe(false);
    expect(salvageFileRecord(null).ok).toBe(false);
  });
});

describe("runMetaSchema", () => {
  it("accepts valid scan run meta", () => {
    const valid = {
      runId: "20260401-a1b2",
      projectId: "test",
      rootPath: "/path/to/project",
      createdAt: "2026-04-01T14:30:52.000Z",
      type: "scan",
      phase: "running",
      scannerConfig: { matcherSlugs: ["xss", "rce"] },
      stats: {},
    };
    expect(() => runMetaSchema.parse(valid)).not.toThrow();
  });

  it("accepts completed process run meta", () => {
    const valid = {
      runId: "20260401-a1b2",
      projectId: "test",
      rootPath: "/path",
      createdAt: "2026-04-01T14:30:52.000Z",
      completedAt: "2026-04-01T15:00:00.000Z",
      type: "process",
      phase: "done",
      processorConfig: {
        agentType: "claude-agent-sdk",
        model: "claude-opus-4-6",
        modelConfig: { maxTurns: 50 },
      },
      stats: { filesProcessed: 3, findingsCount: 2 },
    };
    expect(() => runMetaSchema.parse(valid)).not.toThrow();
  });
});

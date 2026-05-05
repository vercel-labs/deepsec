import { describe, expect, it } from "vitest";
import { fileRecordSchema, runMetaSchema } from "../schemas.js";

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

  it("accepts partial process run meta with failed file count", () => {
    const valid = {
      runId: "20260401-a1b2",
      projectId: "test",
      rootPath: "/path",
      createdAt: "2026-04-01T14:30:52.000Z",
      completedAt: "2026-04-01T15:00:00.000Z",
      type: "process",
      phase: "partial",
      processorConfig: {
        agentType: "claude-agent-sdk",
        model: "claude-opus-4-6",
        modelConfig: { maxTurns: 50 },
      },
      stats: { filesProcessed: 3, filesFailed: 2, findingsCount: 1 },
    };
    expect(() => runMetaSchema.parse(valid)).not.toThrow();
  });
});

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { AnalysisEntry, FileRecord, Finding } from "@deepsec/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  mergeAfterExtract,
  mergeFileRecord,
  snapshotFileRecords,
} from "../sandbox/merge-records.js";

function entry(runId: string, agentType: string, investigatedAt: string): AnalysisEntry {
  return {
    runId,
    investigatedAt,
    durationMs: 1000,
    agentType,
    model: agentType === "codex" ? "gpt-5.5" : "claude-opus-4-7",
    modelConfig: {},
    findingCount: 0,
  };
}

function finding(vulnSlug: string, title: string, extras: Partial<Finding> = {}): Finding {
  return {
    severity: "HIGH",
    vulnSlug,
    title,
    description: "d",
    lineNumbers: [1],
    recommendation: "r",
    confidence: "high",
    ...extras,
  };
}

function record(overrides: Partial<FileRecord> = {}): FileRecord {
  return {
    filePath: "src/foo.ts",
    projectId: "p",
    candidates: [],
    lastScannedAt: "2026-05-06T15:00:00.000Z",
    lastScannedRunId: "scan1",
    fileHash: "h",
    findings: [],
    analysisHistory: [],
    status: "pending",
    ...overrides,
  };
}

describe("mergeFileRecord", () => {
  it("unions analysisHistory by runId and sorts by investigatedAt", () => {
    const host = record({
      analysisHistory: [entry("claude-run", "claude-agent-sdk", "2026-05-06T15:54:37.000Z")],
      status: "analyzed",
    });
    const incoming = record({
      analysisHistory: [entry("codex-run", "codex", "2026-05-06T15:59:48.000Z")],
      status: "analyzed",
    });

    const merged = mergeFileRecord(host, incoming);

    expect(merged.analysisHistory.map((e) => e.runId)).toEqual(["claude-run", "codex-run"]);
    expect(merged.status).toBe("analyzed");
  });

  it("dedupes analysisHistory when both sides serialize the same runId", () => {
    const sameEntry = entry("run-x", "codex", "2026-05-06T15:59:48.000Z");
    const host = record({ analysisHistory: [sameEntry] });
    const incoming = record({
      analysisHistory: [{ ...sameEntry, findingCount: 5 }],
    });

    const merged = mergeFileRecord(host, incoming);

    expect(merged.analysisHistory).toHaveLength(1);
    expect(merged.analysisHistory[0].findingCount).toBe(5); // incoming wins
  });

  it("unions findings by vulnSlug+title signature", () => {
    const host = record({
      findings: [finding("xss", "XSS via innerHTML")],
    });
    const incoming = record({
      findings: [finding("ssrf", "SSRF in webhook handler")],
    });

    const merged = mergeFileRecord(host, incoming);

    expect(merged.findings.map((f) => f.vulnSlug).sort()).toEqual(["ssrf", "xss"]);
  });

  it("preserves revalidation/triage from either side when finding signatures match", () => {
    const hostFinding = finding("xss", "XSS", {
      revalidation: {
        verdict: "true-positive",
        reasoning: "confirmed",
        revalidatedAt: "2026-05-06T16:00:00.000Z",
        runId: "reval-run",
        model: "gpt-5.5",
      },
    });
    const incomingFinding = finding("xss", "xss", {
      triage: {
        priority: "P0",
        exploitability: "trivial",
        impact: "critical",
        reasoning: "trivial RCE",
        triagedAt: "2026-05-06T16:05:00.000Z",
        model: "claude-sonnet-4-6",
      },
    });

    const merged = mergeFileRecord(
      record({ findings: [hostFinding] }),
      record({ findings: [incomingFinding] }),
    );

    expect(merged.findings).toHaveLength(1);
    expect(merged.findings[0].revalidation?.verdict).toBe("true-positive");
    expect(merged.findings[0].triage?.priority).toBe("P0");
  });

  it("preserves gitInfo when incoming lacks it", () => {
    const host = record({
      gitInfo: {
        recentCommitters: [{ name: "alice", email: "a@x", date: "2026-05-06" }],
        enrichedAt: "2026-05-06T15:00:00.000Z",
      },
    });
    const incoming = record({ gitInfo: undefined });

    const merged = mergeFileRecord(host, incoming);

    expect(merged.gitInfo?.recentCommitters[0].name).toBe("alice");
  });

  it("status: 'analyzed' on either side wins", () => {
    expect(
      mergeFileRecord(record({ status: "analyzed" }), record({ status: "processing" })).status,
    ).toBe("analyzed");
    expect(
      mergeFileRecord(record({ status: "pending" }), record({ status: "analyzed" })).status,
    ).toBe("analyzed");
    expect(
      mergeFileRecord(record({ status: "processing" }), record({ status: "error" })).status,
    ).toBe("error");
  });

  it("reproduces the parallel-orchestrator scenario end-to-end", () => {
    // Repro: claude orchestrator finished a sandbox at 15:54:37 (host
    // gets [claudeA]). Codex orchestrator started at 15:58:21, snapshotted
    // the host (got [claudeA]), processed and is now uploading [claudeA, codexB].
    //
    // Meanwhile, ANOTHER claude sandbox started before 15:58:21 (so its
    // local snapshot was empty) finished and is uploading [claudeC]. If
    // its tarball lands AFTER codex's, the naive overwrite drops both
    // claudeA and codexB. With the merge, all three survive.
    let host = record({
      analysisHistory: [entry("claudeA", "claude-agent-sdk", "2026-05-06T15:54:37.000Z")],
      status: "analyzed",
    });

    // Codex sandbox uploads [claudeA, codexB] — extract overlays it on host
    const codexUpload = record({
      analysisHistory: [
        entry("claudeA", "claude-agent-sdk", "2026-05-06T15:54:37.000Z"),
        entry("codexB", "codex", "2026-05-06T15:59:48.000Z"),
      ],
      status: "analyzed",
    });
    host = mergeFileRecord(host, codexUpload);

    // Late-arriving claude sandbox uploads [claudeC] only (its local snapshot
    // had been empty when the run started)
    const lateClaudeUpload = record({
      analysisHistory: [entry("claudeC", "claude-agent-sdk", "2026-05-06T16:02:00.000Z")],
      status: "analyzed",
    });
    host = mergeFileRecord(host, lateClaudeUpload);

    expect(host.analysisHistory.map((e) => e.runId)).toEqual(["claudeA", "codexB", "claudeC"]);
  });
});

describe("snapshotFileRecords + mergeAfterExtract", () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-merge-"));
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("returns an empty snapshot when files/ doesn't exist", () => {
    expect(snapshotFileRecords(dir).size).toBe(0);
  });

  it("walks files/ recursively and indexes records by relative path", () => {
    const inner = path.join(dir, "files", "src", "nested");
    fs.mkdirSync(inner, { recursive: true });
    fs.writeFileSync(
      path.join(inner, "deep.ts.json"),
      JSON.stringify(record({ filePath: "src/nested/deep.ts" })),
    );
    fs.writeFileSync(
      path.join(dir, "files", "shallow.ts.json"),
      JSON.stringify(record({ filePath: "shallow.ts" })),
    );

    const snap = snapshotFileRecords(dir);

    expect(snap.size).toBe(2);
    expect(snap.has(path.join("files", "src", "nested", "deep.ts.json"))).toBe(true);
    expect(snap.has(path.join("files", "shallow.ts.json"))).toBe(true);
  });

  it("rewrites only files that existed in both the host snapshot and the post-extract state", () => {
    // Pre-extraction: host has a record with claude history
    const filesDir = path.join(dir, "files", "src");
    fs.mkdirSync(filesDir, { recursive: true });
    const recPath = path.join(filesDir, "foo.ts.json");
    fs.writeFileSync(
      recPath,
      JSON.stringify(
        record({
          filePath: "src/foo.ts",
          analysisHistory: [entry("claudeA", "claude-agent-sdk", "2026-05-06T15:54:37.000Z")],
          status: "analyzed",
        }),
      ),
    );
    const snap = snapshotFileRecords(dir);

    // Simulate a tar extract overwriting that file with [codexB] only —
    // the pattern that drops history without merging.
    fs.writeFileSync(
      recPath,
      JSON.stringify(
        record({
          filePath: "src/foo.ts",
          analysisHistory: [entry("codexB", "codex", "2026-05-06T15:59:48.000Z")],
          status: "analyzed",
        }),
      ),
    );

    // A second file the host had nothing for (sandbox-only contribution)
    const newFilePath = path.join(filesDir, "bar.ts.json");
    fs.writeFileSync(
      newFilePath,
      JSON.stringify(
        record({
          filePath: "src/bar.ts",
          analysisHistory: [entry("codexB2", "codex", "2026-05-06T15:59:50.000Z")],
        }),
      ),
    );

    const merged = mergeAfterExtract(dir, snap, "p");
    expect(merged).toBe(1);

    const fooAfter = JSON.parse(fs.readFileSync(recPath, "utf-8"));
    expect(fooAfter.analysisHistory.map((e: AnalysisEntry) => e.runId)).toEqual([
      "claudeA",
      "codexB",
    ]);

    // bar.ts wasn't in the host snapshot, so it's left alone.
    const barAfter = JSON.parse(fs.readFileSync(newFilePath, "utf-8"));
    expect(barAfter.analysisHistory.map((e: AnalysisEntry) => e.runId)).toEqual(["codexB2"]);
  });

  it("skips malformed JSON in the snapshot rather than throwing", () => {
    const filesDir = path.join(dir, "files");
    fs.mkdirSync(filesDir, { recursive: true });
    fs.writeFileSync(path.join(filesDir, "broken.ts.json"), "{not valid json");
    fs.writeFileSync(path.join(filesDir, "ok.ts.json"), JSON.stringify(record()));

    const snap = snapshotFileRecords(dir);
    expect(snap.size).toBe(1);
  });

  it("restores the host record when incoming JSON declares a traversal filePath", () => {
    const filesDir = path.join(dir, "files");
    fs.mkdirSync(filesDir, { recursive: true });
    const recPath = path.join(filesDir, "foo.ts.json");
    const host = record({
      filePath: "foo.ts",
      analysisHistory: [entry("host", "codex", "2026-05-06T15:00:00.000Z")],
    });
    fs.writeFileSync(recPath, JSON.stringify(host));
    const snap = snapshotFileRecords(dir);

    fs.writeFileSync(
      recPath,
      JSON.stringify({
        ...record({ filePath: "foo.ts" }),
        filePath: "src/../foo.ts",
        analysisHistory: [entry("sandbox", "claude", "2026-05-06T16:00:00.000Z")],
      }),
    );

    const merged = mergeAfterExtract(dir, snap, "p");
    expect(merged).toBe(0);
    const after = JSON.parse(fs.readFileSync(recPath, "utf-8")) as FileRecord;
    expect(after.filePath).toBe("foo.ts");
    expect(after.analysisHistory.map((e) => e.runId)).toEqual(["host"]);
  });
});

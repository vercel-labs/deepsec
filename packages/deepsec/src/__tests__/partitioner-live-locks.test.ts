import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { type FileRecord, writeFileRecord } from "@deepsec/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { hasLiveLock, partitionFiles } from "../sandbox/partitioner.js";

const P = "proj";

describe("partitionFiles skips files another run is still working on", () => {
  let prev: string | undefined;
  let tmp: string;

  beforeEach(() => {
    prev = process.env.DEEPSEC_DATA_ROOT;
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-part-"));
    process.env.DEEPSEC_DATA_ROOT = tmp;
    fs.mkdirSync(path.join(tmp, P, "runs"), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, P, "project.json"),
      JSON.stringify({ projectId: P, rootPath: tmp, createdAt: new Date(0).toISOString() }),
    );
  });

  afterEach(() => {
    if (prev === undefined) delete process.env.DEEPSEC_DATA_ROOT;
    else process.env.DEEPSEC_DATA_ROOT = prev;
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  function meta(runId: string, phase: "running" | "done", hostname = "sandbox-host") {
    fs.writeFileSync(
      path.join(tmp, P, "runs", `${runId}.json`),
      JSON.stringify({
        runId,
        projectId: P,
        rootPath: "/vercel/sandbox/target",
        createdAt: new Date().toISOString(),
        type: "process",
        phase,
        pid: 23,
        hostname,
        stats: {},
      }),
    );
  }

  function rec(
    filePath: string,
    status: FileRecord["status"],
    lock?: { run: string; ageMs: number },
  ): FileRecord {
    const r: FileRecord = {
      filePath,
      projectId: P,
      candidates: [
        { vulnSlug: "auth-bypass", lineNumbers: [1], snippet: "x", matchedPattern: "p" },
      ],
      lastScannedAt: new Date().toISOString(),
      lastScannedRunId: "scan",
      fileHash: "h",
      findings: [],
      analysisHistory: [],
      status,
    };
    if (lock) {
      r.lockedByRunId = lock.run;
      r.lockedAt = new Date(Date.now() - lock.ageMs).toISOString();
    }
    writeFileRecord(r);
    return r;
  }

  it("leaves out files locked by a running sandbox worker, even past the processor's 1h cutoff", () => {
    meta("run-live", "running");
    meta("run-done", "done");
    rec("pending.ts", "pending");
    rec("error.ts", "error");
    rec("live-recent.ts", "processing", { run: "run-live", ageMs: 5 * 60_000 });
    rec("live-90min.ts", "processing", { run: "run-live", ageMs: 90 * 60_000 });
    rec("done-owner.ts", "processing", { run: "run-done", ageMs: 5 * 60_000 });
    rec("missing-owner.ts", "processing", { run: "run-gone", ageMs: 5 * 60_000 });
    rec("ancient.ts", "processing", { run: "run-live", ageMs: 7 * 60 * 60_000 });

    const { partitions } = partitionFiles(P, 1, { command: "process" });
    expect(partitions.flat().sort()).toEqual(
      ["ancient.ts", "done-owner.ts", "error.ts", "missing-owner.ts", "pending.ts"].sort(),
    );
  });

  it("applies to --reinvestigate waves too", () => {
    meta("run-live", "running");
    rec("a.ts", "analyzed");
    rec("b.ts", "processing", { run: "run-live", ageMs: 60_000 });
    const { partitions } = partitionFiles(P, 1, { command: "process", reinvestigate: 7 });
    expect(partitions.flat()).toEqual(["a.ts"]);
  });

  it("treats a dead local PID as reclaimable", () => {
    meta("run-local", "running", os.hostname());
    // pid 23 belongs to the test fixture's meta; use one that can't exist.
    const r = rec("c.ts", "processing", { run: "run-local", ageMs: 60_000 });
    const f = path.join(tmp, P, "runs", "run-local.json");
    const m = JSON.parse(fs.readFileSync(f, "utf8"));
    m.pid = 2 ** 22 + 12345;
    fs.writeFileSync(f, JSON.stringify(m));
    expect(hasLiveLock(P, r)).toBe(false);
  });
});

describe("partitionFiles for revalidate skips files other active revalidations hold", () => {
  let prev: string | undefined;
  let tmp: string;
  beforeEach(() => {
    prev = process.env.DEEPSEC_DATA_ROOT;
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-part-rv-"));
    process.env.DEEPSEC_DATA_ROOT = tmp;
    fs.mkdirSync(path.join(tmp, P, "sandbox-runs"), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, P, "project.json"),
      JSON.stringify({ projectId: P, rootPath: tmp, createdAt: new Date(0).toISOString() }),
    );
    for (const f of ["held.ts", "free.ts", "stale.ts"]) {
      writeFileRecord({
        filePath: f,
        projectId: P,
        candidates: [
          { vulnSlug: "auth-bypass", lineNumbers: [1], snippet: "x", matchedPattern: "p" },
        ],
        lastScannedAt: new Date().toISOString(),
        lastScannedRunId: "scan",
        fileHash: "h",
        findings: [
          {
            severity: "HIGH",
            vulnSlug: "auth-bypass",
            title: "t",
            description: "d",
            lineNumbers: [1],
            recommendation: "r",
            confidence: "high",
          },
        ],
        analysisHistory: [],
        status: "analyzed",
      } as FileRecord);
    }
    const state = (runId: string, launchedAt: string, files: string[]) =>
      fs.writeFileSync(
        path.join(tmp, P, "sandbox-runs", `${runId}.json`),
        JSON.stringify({
          runId,
          projectId: P,
          command: "revalidate",
          vcpus: 2,
          launchedAt,
          sandboxes: [{ sandboxId: "s", cmdId: "c", index: 0, manifest: files }],
        }),
      );
    state("sbx-live", new Date().toISOString(), ["held.ts"]);
    state("sbx-old", new Date(Date.now() - 7 * 60 * 60_000).toISOString(), ["stale.ts"]);
  });
  afterEach(() => {
    if (prev === undefined) delete process.env.DEEPSEC_DATA_ROOT;
    else process.env.DEEPSEC_DATA_ROOT = prev;
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it("excludes held files, ignores stale states, and leaves process alone", () => {
    expect(partitionFiles(P, 1, { command: "revalidate" }).partitions.flat().sort()).toEqual([
      "free.ts",
      "stale.ts",
    ]);
    expect(
      partitionFiles(P, 1, { command: "process", reinvestigate: true }).partitions.flat().sort(),
    ).toEqual(["free.ts", "held.ts", "stale.ts"]);
  });
});

describe("partitionFiles respects files other process runs have assigned", () => {
  let prev: string | undefined;
  let tmp: string;
  const hoursAgo = (h: number) => new Date(Date.now() - h * 60 * 60_000).toISOString();

  beforeEach(() => {
    prev = process.env.DEEPSEC_DATA_ROOT;
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-part-proc-"));
    process.env.DEEPSEC_DATA_ROOT = tmp;
    fs.mkdirSync(path.join(tmp, P, "sandbox-runs"), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, P, "project.json"),
      JSON.stringify({ projectId: P, rootPath: tmp, createdAt: new Date(0).toISOString() }),
    );
    for (const f of ["free.ts", "reserved.ts", "late.ts", "expired.ts", "reval.ts"]) {
      writeFileRecord({
        filePath: f,
        projectId: P,
        candidates: [
          { vulnSlug: "auth-bypass", lineNumbers: [1], snippet: "x", matchedPattern: "p" },
        ],
        lastScannedAt: new Date().toISOString(),
        lastScannedRunId: "scan",
        fileHash: "h",
        findings: [],
        analysisHistory: [],
        status: "pending",
      } as FileRecord);
    }
    const write = (runId: string, body: Record<string, unknown>) =>
      fs.writeFileSync(
        path.join(tmp, P, "sandbox-runs", `${runId}.json`),
        JSON.stringify({ runId, projectId: P, vcpus: 2, sandboxes: [], ...body }),
      );
    // Still bootstrapping: nothing dispatched, so no locks exist yet.
    write("sbx-ramp", {
      command: "process",
      launchedAt: new Date().toISOString(),
      reserved: [{ index: 0, manifest: ["reserved.ts"] }],
    });
    // Launched long ago, but this worker was dispatched late in a slow ramp.
    write("sbx-slow", {
      command: "process",
      launchedAt: hoursAgo(7),
      sandboxes: [
        {
          sandboxId: "s1",
          cmdId: "c1",
          index: 0,
          manifest: ["late.ts"],
          dispatchedAt: hoursAgo(1),
        },
        {
          sandboxId: "s2",
          cmdId: "c2",
          index: 1,
          manifest: ["expired.ts"],
          dispatchedAt: hoursAgo(7),
        },
      ],
      reserved: [{ index: 2, manifest: ["expired.ts"] }],
    });
    write("sbx-reval", {
      command: "revalidate",
      launchedAt: new Date().toISOString(),
      sandboxes: [{ sandboxId: "s3", cmdId: "c3", index: 0, manifest: ["reval.ts"] }],
    });
  });

  afterEach(() => {
    if (prev === undefined) delete process.env.DEEPSEC_DATA_ROOT;
    else process.env.DEEPSEC_DATA_ROOT = prev;
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it("skips reserved and recently dispatched files, but not expired ones or other commands'", () => {
    expect(partitionFiles(P, 1, { command: "process" }).partitions.flat().sort()).toEqual([
      "expired.ts",
      "free.ts",
      "reval.ts",
    ]);
  });
});

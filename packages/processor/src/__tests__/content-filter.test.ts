import { getEventListeners } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { defineConfig, type FileRecord, setLoadedConfig } from "@deepsec/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  ContentFilterBrake,
  ContentFilteredError,
  isContentFilterBlock,
  QuotaExhaustedError,
} from "../agents/shared.js";
import type { InvestigateParams } from "../agents/types.js";
import { process as processProject } from "../index.js";
import { StubAgent } from "./stub-agent.js";

const FLAGGED =
  "This content was flagged for possible cybersecurity risk. If this seems wrong, try rephrasing your request.";

function setupProject(files: string[]) {
  const projectId = "cf-proj";
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-cf-"));
  const targetRoot = path.join(tmp, "target");
  const dataRoot = path.join(tmp, "data");
  fs.mkdirSync(path.join(dataRoot, projectId, "files"), { recursive: true });
  for (const f of files) {
    fs.mkdirSync(path.dirname(path.join(targetRoot, f)), { recursive: true });
    fs.writeFileSync(path.join(targetRoot, f), "// test file\n");
  }
  fs.writeFileSync(
    path.join(dataRoot, projectId, "project.json"),
    JSON.stringify({ projectId, rootPath: targetRoot, createdAt: new Date().toISOString() }),
  );
  process.env.DEEPSEC_DATA_ROOT = dataRoot;
  const recordPath = (rel: string) => path.join(dataRoot, projectId, "files", `${rel}.json`);
  for (const filePath of files) {
    const rec: FileRecord = {
      filePath,
      projectId,
      candidates: [
        { vulnSlug: "auth-bypass", lineNumbers: [1], snippet: "// stub", matchedPattern: "p" },
      ],
      lastScannedAt: new Date().toISOString(),
      lastScannedRunId: "scan-fixture",
      fileHash: "fixture-hash",
      findings: [],
      analysisHistory: [],
      status: "pending",
    };
    fs.writeFileSync(recordPath(filePath), JSON.stringify(rec));
  }
  const read = (rel: string): FileRecord => JSON.parse(fs.readFileSync(recordPath(rel), "utf-8"));
  return { projectId, targetRoot, read };
}

function okResult(params: InvestigateParams) {
  return {
    results: params.batch.map((r) => ({ filePath: r.filePath, findings: [] })),
    meta: { durationMs: 1 },
  };
}

function useStub(
  fx: { projectId: string; targetRoot: string },
  impl: (p: InvestigateParams) => unknown,
) {
  const stub = new StubAgent({
    investigateImpl: async function* (params) {
      return impl(params) as any;
    },
  });
  setLoadedConfig(
    defineConfig({
      projects: [{ id: fx.projectId, root: fx.targetRoot }],
      plugins: [{ name: "stub-plugin", agents: [stub] }],
    }),
  );
  return stub;
}

describe("process() with provider content-filter blocks", () => {
  let prev: Record<string, string | undefined>;

  beforeEach(() => {
    prev = {
      DEEPSEC_DATA_ROOT: process.env.DEEPSEC_DATA_ROOT,
      DEEPSEC_CONTENT_FILTER_PAUSE_MS: process.env.DEEPSEC_CONTENT_FILTER_PAUSE_MS,
    };
    process.env.DEEPSEC_CONTENT_FILTER_PAUSE_MS = "0";
  });

  afterEach(() => {
    for (const [k, v] of Object.entries(prev)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    setLoadedConfig(defineConfig({ projects: [] }));
  });

  it("retries a blocked batch one file at a time and only fails the file that stays blocked", async () => {
    const files = ["a.ts", "b.ts", "c.ts"];
    const fx = setupProject(files);
    const stub = useStub(fx, (params) => {
      if (params.batch.some((r) => r.filePath === "b.ts")) throw new ContentFilteredError(FLAGGED);
      return okResult(params);
    });

    const progress: string[] = [];
    const result = await processProject({
      projectId: fx.projectId,
      agentType: "stub",
      concurrency: 1,
      batchSize: 5,
      onProgress: (p) => progress.push(p.message),
    });

    expect(fx.read("a.ts").status).toBe("analyzed");
    expect(fx.read("c.ts").status).toBe("analyzed");
    expect(fx.read("b.ts").status).toBe("error");
    expect(fx.read("b.ts").analysisHistory).toHaveLength(0);
    expect(result.analysisCount).toBe(2);
    // b.ts was never reviewed, so the run must not look clean to CI.
    expect(result.errorBatchCount).toBe(1);
    expect(
      progress.some((m) => /1 file\(s\) not analyzed after content-filter retries/.test(m)),
    ).toBe(true);
    // 1 batch call, then a.ts, b.ts twice, c.ts.
    expect(
      stub.calls.investigateCalls.map((c) => c.batch.map((r) => r.filePath).join(",")),
    ).toEqual(["a.ts,b.ts,c.ts", "a.ts", "b.ts", "b.ts", "c.ts"]);
    expect(progress.some((m) => /retrying 3 files one at a time/.test(m))).toBe(true);
    expect(progress.some((m) => /blocked by provider content filter/.test(m))).toBe(true);
  });

  it("splits a big blocked batch into chunks and only goes file-by-file in the blocked chunk", async () => {
    const files = Array.from({ length: 12 }, (_, n) => `f${String(n).padStart(2, "0")}.ts`);
    const fx = setupProject(files);
    const stub = useStub(fx, (params) => {
      if (params.batch.some((r) => r.filePath === "f07.ts"))
        throw new ContentFilteredError(FLAGGED);
      return okResult(params);
    });
    const progress: string[] = [];
    const result = await processProject({
      projectId: fx.projectId,
      agentType: "stub",
      concurrency: 1,
      batchSize: 12,
      onProgress: (p) => progress.push(p.message),
    });
    expect(stub.calls.investigateCalls.map((c) => c.batch.length)).toEqual([
      12, 5, 5, 1, 1, 1, 1, 1, 1, 2,
    ]);
    expect(fx.read("f07.ts").status).toBe("error");
    for (const f of files.filter((f) => f !== "f07.ts")) expect(fx.read(f).status).toBe("analyzed");
    expect(result.analysisCount).toBe(11);
    expect(result.errorBatchCount).toBe(1);
    expect(progress.some((m) => /retrying 12 files in chunks of 5/.test(m))).toBe(true);
    expect(progress.some((m) => /retrying 5 files one at a time/.test(m))).toBe(true);
  });

  it("retries a blocked single-file batch", async () => {
    const fx = setupProject(["a.ts"]);
    let calls = 0;
    useStub(fx, (params) => {
      calls++;
      if (calls === 1) throw new ContentFilteredError(FLAGGED);
      return okResult(params);
    });

    const result = await processProject({
      projectId: fx.projectId,
      agentType: "stub",
      concurrency: 1,
    });
    expect(calls).toBe(2);
    expect(fx.read("a.ts").status).toBe("analyzed");
    expect(result.errorBatchCount).toBe(0);
  });

  it("reports a clean batch when every blocked file succeeds on retry", async () => {
    const fx = setupProject(["a.ts", "b.ts", "c.ts"]);
    let blockedOnce = false;
    useStub(fx, (params) => {
      if (params.batch.length > 1 && !blockedOnce) {
        blockedOnce = true;
        throw new ContentFilteredError(FLAGGED);
      }
      return okResult(params);
    });
    const result = await processProject({
      projectId: fx.projectId,
      agentType: "stub",
      concurrency: 1,
    });
    expect(result.analysisCount).toBe(3);
    expect(result.errorBatchCount).toBe(0);
  });

  it("fails the batch when a retried file errors for another reason", async () => {
    const fx = setupProject(["a.ts", "b.ts", "c.ts"]);
    useStub(fx, (params) => {
      if (params.batch.length > 1) throw new ContentFilteredError(FLAGGED);
      if (params.batch[0].filePath === "c.ts") throw new Error("agent crashed");
      return okResult(params);
    });
    const result = await processProject({
      projectId: fx.projectId,
      agentType: "stub",
      concurrency: 1,
    });
    expect(fx.read("a.ts").status).toBe("analyzed");
    expect(fx.read("b.ts").status).toBe("analyzed");
    expect(fx.read("c.ts").status).toBe("error");
    expect(result.analysisCount).toBe(2);
    expect(result.errorBatchCount).toBe(1);
  });

  it("fails the batch when every file stays blocked, without recording any as clean", async () => {
    const fx = setupProject(["a.ts", "b.ts"]);
    useStub(fx, () => {
      throw new ContentFilteredError(FLAGGED);
    });

    const result = await processProject({
      projectId: fx.projectId,
      agentType: "stub",
      concurrency: 1,
    });
    expect(result.analysisCount).toBe(0);
    expect(result.errorBatchCount).toBe(1);
    expect(fx.read("a.ts").status).toBe("error");
    expect(fx.read("b.ts").status).toBe("error");
  });

  it("stops the run when quota runs out during content-filter retries", async () => {
    const fx = setupProject(["a.ts", "b.ts", "c.ts"]);
    const stub = useStub(fx, (params) => {
      if (params.batch.length > 1) throw new ContentFilteredError(FLAGGED);
      if (params.batch[0].filePath === "b.ts")
        throw new QuotaExhaustedError("anthropic-credits", "credit balance is too low");
      return okResult(params);
    });
    const result = await processProject({
      projectId: fx.projectId,
      agentType: "stub",
      concurrency: 1,
    });
    expect(result.quotaExhausted?.source).toBe("anthropic-credits");
    expect(fx.read("a.ts").status).toBe("analyzed");
    expect(fx.read("b.ts").status).toBe("error");
    // c.ts is never sent against the exhausted credential.
    expect(
      stub.calls.investigateCalls.map((c) => c.batch.map((r) => r.filePath).join(",")),
    ).toEqual(["a.ts,b.ts,c.ts", "a.ts", "b.ts"]);
    expect(fx.read("c.ts").status).not.toBe("analyzed");
  });

  it("checks the cost limit between content-filter retries", async () => {
    const fx = setupProject(["a.ts", "b.ts", "c.ts"]);
    const stub = useStub(fx, (params) => {
      if (params.batch.length > 1) throw new ContentFilteredError(FLAGGED);
      return { ...okResult(params), meta: { durationMs: 1, costUsd: 1 } };
    });
    const result = await processProject({
      projectId: fx.projectId,
      agentType: "stub",
      concurrency: 1,
      maxCostUsd: 1,
    });
    expect(result.costLimitReached?.limitUsd).toBe(1);
    expect(stub.calls.investigateCalls).toHaveLength(2);
    expect(fx.read("a.ts").status).toBe("analyzed");
  });

  it("renews this run's locks during long retries, but not another run's", async () => {
    process.env.DEEPSEC_CONTENT_FILTER_PAUSE_MS = "20";
    const fx = setupProject(["a.ts", "b.ts", "c.ts"]);
    const seen: Record<string, string[]> = { "c.ts": [] };
    let bLockAtRetry: string | undefined;
    useStub(fx, (params) => {
      seen["c.ts"].push(fx.read("c.ts").lockedAt ?? "");
      if (params.batch.length === 1 && params.batch[0].filePath === "b.ts")
        bLockAtRetry = fx.read("b.ts").lockedAt;
      if (params.batch.length > 1) {
        // Another run takes over b.ts while this batch is blocked.
        const b = fx.read("b.ts");
        b.lockedByRunId = "other-run";
        b.lockedAt = "2000-01-01T00:00:00.000Z";
        fs.writeFileSync(
          path.join(process.env.DEEPSEC_DATA_ROOT ?? "", fx.projectId, "files", "b.ts.json"),
          JSON.stringify(b),
        );
        throw new ContentFilteredError(FLAGGED);
      }
      return okResult(params);
    });
    await processProject({ projectId: fx.projectId, agentType: "stub", concurrency: 1 });
    const [atClaim, ...atRetries] = seen["c.ts"];
    expect(atRetries.length).toBeGreaterThan(0);
    for (const at of atRetries) expect(Date.parse(at)).toBeGreaterThan(Date.parse(atClaim));
    expect(bLockAtRetry).toBe("2000-01-01T00:00:00.000Z");
  });

  it("holds back the next batch while the brake is on", async () => {
    process.env.DEEPSEC_CONTENT_FILTER_PAUSE_MS = "300";
    const fx = setupProject(["a.ts", "b.ts"]);
    const startedAt: number[] = [];
    useStub(fx, (params) => {
      startedAt.push(Date.now());
      if (params.batch[0].filePath === "a.ts" && startedAt.length === 1) {
        throw new ContentFilteredError(FLAGGED);
      }
      return okResult(params);
    });

    await processProject({
      projectId: fx.projectId,
      agentType: "stub",
      concurrency: 1,
      batchSize: 1,
    });
    // a.ts blocked, a.ts retried after the pause, then b.ts.
    expect(startedAt).toHaveLength(3);
    expect(startedAt[1] - startedAt[0]).toBeGreaterThanOrEqual(200);
    expect(fx.read("a.ts").status).toBe("analyzed");
    expect(fx.read("b.ts").status).toBe("analyzed");
  });
});

describe("ContentFilterBrake", () => {
  it("doubles the pause on repeated blocks, caps it, and resets after the window", () => {
    let t = 0;
    const brake = new ContentFilterBrake(
      1000,
      5000,
      60_000,
      () => t,
      () => 0.5,
    );
    expect(brake.noteBlock()).toBe(1000);
    expect(brake.noteBlock()).toBe(2000);
    expect(brake.noteBlock()).toBe(4000);
    expect(brake.noteBlock()).toBe(5000);
    expect(brake.remainingMs()).toBe(5000);
    t = 120_000;
    expect(brake.remainingMs()).toBe(0);
    expect(brake.noteBlock()).toBe(1000);
  });

  it("never exceeds the maximum pause, even with jitter", () => {
    const brake = new ContentFilterBrake(
      1000,
      5000,
      60_000,
      () => 0,
      () => 1,
    );
    for (let n = 0; n < 6; n++) expect(brake.noteBlock()).toBeLessThanOrEqual(5000);
  });

  it("removes its abort listener when a pause ends normally", async () => {
    const brake = new ContentFilterBrake(5, 5);
    const ac = new AbortController();
    for (let n = 0; n < 3; n++) {
      brake.noteBlock();
      await brake.wait(ac.signal);
    }
    expect(getEventListeners(ac.signal, "abort")).toHaveLength(0);
  });

  it("stops waiting when the signal aborts", async () => {
    const brake = new ContentFilterBrake(10_000, 10_000);
    brake.noteBlock();
    const ac = new AbortController();
    const started = Date.now();
    setTimeout(() => ac.abort(), 20);
    await brake.wait(ac.signal);
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it("recognizes the provider's cybersecurity filter message", () => {
    expect(isContentFilterBlock(`{"error":{"message":"${FLAGGED}"}}`)).toBe(true);
    expect(isContentFilterBlock("Reconnecting... 1/5 (stream disconnected)")).toBe(false);
    expect(isContentFilterBlock(undefined)).toBe(false);
  });
});

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { defineConfig, type FileRecord, setLoadedConfig } from "@deepsec/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { process as processProject, revalidate } from "../index.js";
import { StubAgent } from "./stub-agent.js";

interface Fixture {
  tmp: string;
  targetRoot: string;
  projectId: string;
  dataRoot: string;
  recordPath: (relPath: string) => string;
  readRecord: (relPath: string) => FileRecord;
  writeRecord: (rec: FileRecord) => void;
}

function setupProject(opts: { projectId?: string; files?: string[] } = {}): Fixture {
  const projectId = opts.projectId ?? "test-proj";
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-proc-"));
  const targetRoot = path.join(tmp, "target");
  const dataRoot = path.join(tmp, "data");
  fs.mkdirSync(targetRoot, { recursive: true });
  fs.mkdirSync(path.join(dataRoot, projectId, "files"), { recursive: true });

  for (const f of opts.files ?? []) {
    const abs = path.join(targetRoot, f);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, "// test file\n");
  }

  fs.writeFileSync(
    path.join(dataRoot, projectId, "project.json"),
    JSON.stringify({
      projectId,
      rootPath: targetRoot,
      createdAt: new Date().toISOString(),
    }),
  );

  process.env.DEEPSEC_DATA_ROOT = dataRoot;

  const recordPath = (relPath: string) =>
    path.join(dataRoot, projectId, "files", `${relPath}.json`);
  const readRecord = (relPath: string): FileRecord =>
    JSON.parse(fs.readFileSync(recordPath(relPath), "utf-8"));
  const writeRecord = (rec: FileRecord): void => {
    const p = recordPath(rec.filePath);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, JSON.stringify(rec));
  };

  return { tmp, targetRoot, projectId, dataRoot, recordPath, readRecord, writeRecord };
}

function pendingRecord(projectId: string, filePath: string): FileRecord {
  return {
    filePath,
    projectId,
    candidates: [
      {
        vulnSlug: "auth-bypass",
        lineNumbers: [1],
        snippet: "// stub",
        matchedPattern: "test pattern",
      },
    ],
    lastScannedAt: new Date().toISOString(),
    lastScannedRunId: "scan-fixture",
    fileHash: "fixture-hash",
    findings: [],
    analysisHistory: [],
    status: "pending",
  };
}

describe("processor with stub agent", () => {
  let prevDataRoot: string | undefined;

  beforeEach(() => {
    prevDataRoot = process.env.DEEPSEC_DATA_ROOT;
  });

  afterEach(() => {
    if (prevDataRoot === undefined) delete process.env.DEEPSEC_DATA_ROOT;
    else process.env.DEEPSEC_DATA_ROOT = prevDataRoot;
    setLoadedConfig(defineConfig({ projects: [] }));
  });

  it("process() runs the agent, persists findings + AnalysisEntry, marks files analyzed", async () => {
    const fx = setupProject({ files: ["app.ts"] });
    fx.writeRecord(pendingRecord(fx.projectId, "app.ts"));

    const stub = new StubAgent();
    setLoadedConfig(
      defineConfig({
        projects: [{ id: fx.projectId, root: fx.targetRoot }],
        plugins: [{ name: "stub-plugin", agents: [stub] }],
      }),
    );

    const result = await processProject({
      projectId: fx.projectId,
      agentType: "stub",
      concurrency: 1,
    });

    expect(result.findingCount).toBe(1);
    expect(result.analysisCount).toBe(1);
    expect(result.failedCount).toBe(0);
    expect(result.phase).toBe("done");
    expect(stub.calls.investigateCalls).toHaveLength(1);
    expect(stub.calls.investigateCalls[0].batch).toHaveLength(1);

    const rec = fx.readRecord("app.ts");
    expect(rec.status).toBe("analyzed");
    expect(rec.findings).toHaveLength(1);
    expect(rec.findings[0].severity).toBe("HIGH");
    expect(rec.findings[0].title).toBe("stub finding for app.ts");
    expect(rec.analysisHistory).toHaveLength(1);
    expect(rec.analysisHistory[0].agentType).toBe("stub");
    expect(rec.analysisHistory[0].findingCount).toBe(1);
    expect(rec.lockedByRunId).toBeFalsy();
  });

  it("process() respects --limit", async () => {
    const fx = setupProject({ files: ["a.ts", "b.ts", "c.ts"] });
    fx.writeRecord(pendingRecord(fx.projectId, "a.ts"));
    fx.writeRecord(pendingRecord(fx.projectId, "b.ts"));
    fx.writeRecord(pendingRecord(fx.projectId, "c.ts"));

    const stub = new StubAgent();
    setLoadedConfig(
      defineConfig({
        projects: [{ id: fx.projectId, root: fx.targetRoot }],
        plugins: [{ name: "stub", agents: [stub] }],
      }),
    );

    await processProject({
      projectId: fx.projectId,
      agentType: "stub",
      concurrency: 1,
      limit: 2,
    });

    const statuses = ["a.ts", "b.ts", "c.ts"].map((f) => fx.readRecord(f).status);
    const analyzed = statuses.filter((s) => s === "analyzed").length;
    expect(analyzed).toBe(2);
    expect(statuses).toContain("pending");
  });

  it("process() skips already-analyzed files unless --reinvestigate", async () => {
    const fx = setupProject({ files: ["a.ts"] });
    const rec = pendingRecord(fx.projectId, "a.ts");
    rec.status = "analyzed";
    rec.analysisHistory = [
      {
        runId: "earlier",
        investigatedAt: new Date().toISOString(),
        durationMs: 1,
        agentType: "stub",
        model: "stub",
        modelConfig: {},
        findingCount: 0,
        usage: {
          inputTokens: 1,
          outputTokens: 1,
          cacheReadInputTokens: 0,
          cacheCreationInputTokens: 0,
        },
      },
    ];
    fx.writeRecord(rec);

    const stub = new StubAgent();
    setLoadedConfig(
      defineConfig({
        projects: [{ id: fx.projectId, root: fx.targetRoot }],
        plugins: [{ name: "stub", agents: [stub] }],
      }),
    );

    const result = await processProject({
      projectId: fx.projectId,
      agentType: "stub",
      concurrency: 1,
    });

    expect(result.analysisCount).toBe(0);
    expect(stub.calls.investigateCalls).toHaveLength(0);
  });

  it("process() throws a clear error when project root does not exist", async () => {
    const fx = setupProject({ files: ["app.ts"] });
    fx.writeRecord(pendingRecord(fx.projectId, "app.ts"));
    // Wipe the target root so the existence check fires.
    fs.rmSync(fx.targetRoot, { recursive: true, force: true });

    setLoadedConfig(
      defineConfig({
        projects: [{ id: fx.projectId, root: fx.targetRoot }],
        plugins: [{ name: "stub", agents: [new StubAgent()] }],
      }),
    );

    await expect(
      processProject({
        projectId: fx.projectId,
        agentType: "stub",
        concurrency: 1,
      }),
    ).rejects.toThrow(/Project root does not exist/);
  });

  it("process() captures refusals from the agent into AnalysisEntry", async () => {
    const fx = setupProject({ files: ["app.ts"] });
    fx.writeRecord(pendingRecord(fx.projectId, "app.ts"));

    const stub = new StubAgent({
      async *investigateImpl(params) {
        return {
          results: params.batch.map((r) => ({ filePath: r.filePath, findings: [] })),
          meta: {
            durationMs: 1,
            refusal: { refused: true, reason: "stub refusal" },
            usage: {
              inputTokens: 1,
              outputTokens: 1,
              cacheReadInputTokens: 0,
              cacheCreationInputTokens: 0,
            },
          },
        };
      },
    });
    setLoadedConfig(
      defineConfig({
        projects: [{ id: fx.projectId, root: fx.targetRoot }],
        plugins: [{ name: "stub", agents: [stub] }],
      }),
    );

    await processProject({
      projectId: fx.projectId,
      agentType: "stub",
      concurrency: 1,
    });

    const rec = fx.readRecord("app.ts");
    expect(rec.findings).toHaveLength(0);
    expect(rec.analysisHistory[0].refusal?.refused).toBe(true);
    expect(rec.analysisHistory[0].refusal?.reason).toBe("stub refusal");
  });

  it("process() marks batch retryable and run partial on agent error with zero output", async () => {
    const fx = setupProject({ files: ["a.ts", "b.ts"] });
    fx.writeRecord(pendingRecord(fx.projectId, "a.ts"));
    fx.writeRecord(pendingRecord(fx.projectId, "b.ts"));

    const stub = new StubAgent({
      async *investigateImpl(params) {
        return {
          results: params.batch.map((r) => ({ filePath: r.filePath, findings: [] })),
          meta: {
            durationMs: 1,
            hadErrors: true,
            usage: {
              inputTokens: 0,
              outputTokens: 0,
              cacheReadInputTokens: 0,
              cacheCreationInputTokens: 0,
            },
          },
        };
      },
    });
    setLoadedConfig(
      defineConfig({
        projects: [{ id: fx.projectId, root: fx.targetRoot }],
        plugins: [{ name: "stub-plugin", agents: [stub] }],
      }),
    );

    const result = await processProject({
      projectId: fx.projectId,
      agentType: "stub",
      concurrency: 1,
    });

    expect(result.analysisCount).toBe(0);
    expect(result.findingCount).toBe(0);
    expect(result.failedCount).toBe(2);
    expect(result.phase).toBe("partial");
    expect(fx.readRecord("a.ts").status).toBe("error");
    expect(fx.readRecord("b.ts").status).toBe("error");
  });

  it("revalidate() attaches verdicts to existing findings", async () => {
    const fx = setupProject({ files: ["app.ts"] });
    const rec = pendingRecord(fx.projectId, "app.ts");
    rec.status = "analyzed";
    rec.findings = [
      {
        severity: "HIGH",
        vulnSlug: "auth-bypass",
        title: "missing auth on /admin",
        description: "no withAuthentication wrapper",
        lineNumbers: [10],
        recommendation: "wrap with withAuthentication",
        confidence: "high",
      },
    ];
    rec.analysisHistory = [
      {
        runId: "earlier",
        investigatedAt: new Date().toISOString(),
        durationMs: 1,
        agentType: "stub",
        model: "stub",
        modelConfig: {},
        findingCount: 1,
      },
    ];
    fx.writeRecord(rec);

    const stub = new StubAgent();
    setLoadedConfig(
      defineConfig({
        projects: [{ id: fx.projectId, root: fx.targetRoot }],
        plugins: [{ name: "stub", agents: [stub] }],
      }),
    );

    await revalidate({
      projectId: fx.projectId,
      agentType: "stub",
      concurrency: 1,
    });

    expect(stub.calls.revalidateCalls).toHaveLength(1);
    const after = fx.readRecord("app.ts");
    expect(after.findings).toHaveLength(1);
    expect(after.findings[0].revalidation?.verdict).toBe("true-positive");
    expect(after.findings[0].revalidation?.reasoning).toBe("stub: confirmed");
  });

  it("revalidate() skips findings that already have a verdict unless --force", async () => {
    const fx = setupProject({ files: ["app.ts"] });
    const rec = pendingRecord(fx.projectId, "app.ts");
    rec.status = "analyzed";
    rec.findings = [
      {
        severity: "HIGH",
        vulnSlug: "auth-bypass",
        title: "already revalidated",
        description: "x",
        lineNumbers: [1],
        recommendation: "x",
        confidence: "high",
        revalidation: {
          verdict: "true-positive",
          reasoning: "previous run",
          revalidatedAt: new Date().toISOString(),
          runId: "earlier",
          model: "stub",
        },
      },
    ];
    fx.writeRecord(rec);

    const stub = new StubAgent();
    setLoadedConfig(
      defineConfig({
        projects: [{ id: fx.projectId, root: fx.targetRoot }],
        plugins: [{ name: "stub", agents: [stub] }],
      }),
    );

    await revalidate({
      projectId: fx.projectId,
      agentType: "stub",
      concurrency: 1,
    });

    expect(stub.calls.revalidateCalls).toHaveLength(0);
  });
});

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { type FileRecord, setLoadedConfig } from "@deepsec/core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { runSetupWorkflow } from "../setup/coordinator.js";
import type { SetupReporter } from "../setup/reporter.js";
import { digest } from "../setup/state.js";

const originalCwd = process.cwd();
const roots: string[] = [];
afterEach(() => {
  process.chdir(originalCwd);
  setLoadedConfig({ projects: [] });
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-process-checkpoint-"));
  roots.push(root);
  const workspace = path.join(root, ".deepsec");
  const project = path.join(root, "app");
  fs.mkdirSync(path.join(workspace, "data", "app"), { recursive: true });
  fs.mkdirSync(path.join(project, "src"), { recursive: true });
  fs.writeFileSync(path.join(project, "src", "route.ts"), "export const GET = () => 'ok';\n");
  fs.writeFileSync(path.join(workspace, "package.json"), '{"private":true}\n');
  fs.writeFileSync(
    path.join(workspace, "deepsec.config.ts"),
    'export default { projects: [{ id: "app", root: "../app" }] };\n',
  );
  fs.writeFileSync(
    path.join(workspace, "generated-matchers.ts"),
    'export const generatedMatchersPlugin = { name: "generated", matchers: [] };\n',
  );
  const record = {
    filePath: "src/route.ts",
    projectId: "app",
    fileHash: "hash",
    candidates: [
      { vulnSlug: "public-endpoint", lineNumbers: [1], snippet: "GET", matchedPattern: "GET" },
    ],
    lastScannedAt: "now",
    lastScannedRunId: "scan-1",
    findings: [],
    analysisHistory: [],
    status: "pending",
  } as FileRecord;
  const analyze = vi.fn(async () => ({
    infoMarkdown:
      "# app\n\n## What this codebase does\nApp.\n\n## Auth shape\nNone.\n\n## Threat model\nPublic input.\n\n## Project-specific patterns to flag\nRoutes.\n\n## Known false-positives\nNone.",
    surfaces: [
      {
        id: "http",
        kind: "http" as const,
        description: "Routes",
        fileGlobs: ["src/**/*.ts"],
        representativeFiles: ["src/route.ts"],
        exposure: "public" as const,
      },
    ],
    inspectedPaths: ["src/route.ts"],
  }));
  const scan = vi.fn(async () => ({
    runId: "scan-1",
    candidateCount: 1,
    detected: { tags: [], sentinels: [], detectedAt: "now", rootPath: project },
    activeMatchers: ["public-endpoint"],
    skippedMatchers: [],
    languageStats: [],
  }));
  const processCandidates = vi.fn(async () => ({
    runId: "process-ok",
    analysisCount: 1,
    findingCount: 0,
    errorBatchCount: 0,
  }));
  const events: Array<{ type: string; phase?: string }> = [];
  const options = {
    workspaceDir: workspace,
    projectId: "app",
    projectRoot: project,
    agent: "codex" as const,
    model: "test-model",
    thinkingLevel: "low" as const,
    modelRoute: { mode: "local" as const, provider: "local" as const },
    services: {
      install: async () => {
        fs.mkdirSync(path.join(workspace, "node_modules", "deepsec"), { recursive: true });
        return { packageManager: "pnpm" as const, version: "test", installed: true };
      },
      connect: async () => ({ verification: { route: { mode: "local", provider: "local" } } }),
      analyze,
      scan,
      process: processCandidates,
      listFiles: () => ["src/route.ts"],
      fingerprint: () => "source-v1",
      loadRecords: () => [record],
    },
    onLog: () => undefined,
    reporter: {
      interactive: false,
      emit: (event) => {
        events.push(event);
      },
      suspend: async (work) => work(),
      close: async () => undefined,
    } satisfies SetupReporter,
  };
  const stateFile = path.join(workspace, "data", "app", "setup", "setup-state.json");
  const readState = () => JSON.parse(fs.readFileSync(stateFile, "utf8"));
  return { options, processCandidates, analyze, scan, events, readState, stateFile };
}

describe("process checkpoint publication", () => {
  it("reruns legacy process checkpoints while retaining completed earlier phases", async () => {
    const f = fixture();
    await runSetupWorkflow(f.options);
    const legacy = f.readState();
    legacy.phases.process.inputDigest = digest({
      sourceFingerprint: "source-v1",
      scanRunId: "scan-1",
      agentType: "codex",
      model: "test-model",
      thinkingLevel: "low",
    });
    fs.writeFileSync(f.stateFile, JSON.stringify(legacy));

    await runSetupWorkflow(f.options);

    expect(f.processCandidates).toHaveBeenCalledTimes(2);
    expect(f.analyze).toHaveBeenCalledTimes(1);
    expect(f.scan).toHaveBeenCalledTimes(1);
    expect(f.readState().phases.process.inputDigest).not.toBe(legacy.phases.process.inputDigest);
    await runSetupWorkflow(f.options);
    expect(f.processCandidates).toHaveBeenCalledTimes(2);
  });

  it("preserves resumable cost-limit classification when a batch also failed", async () => {
    const f = fixture();
    f.processCandidates.mockResolvedValueOnce({
      runId: "process-limited",
      analysisCount: 0,
      findingCount: 0,
      errorBatchCount: 1,
      costLimitReached: { limitUsd: 1, actualUsd: 1.1 },
    } as Awaited<ReturnType<typeof f.processCandidates>>);
    await expect(runSetupWorkflow({ ...f.options, maxCostUsd: 1 })).rejects.toMatchObject({
      code: "COST_LIMIT_REACHED",
      kind: "limit",
    });
    expect(f.readState().phases.process.status).toBe("error");
    expect(f.readState().processRunId).toBeUndefined();
    await runSetupWorkflow(f.options);
    expect(f.processCandidates).toHaveBeenCalledTimes(2);
  });

  it.each([
    "failed batches",
    "aborted command",
  ])("does not checkpoint %s as successful", async (failure) => {
    const f = fixture();
    const controller = new AbortController();
    f.processCandidates.mockImplementationOnce(async () => {
      if (failure === "aborted command") controller.abort(new Error("Requested pause"));
      return {
        runId: "process-incomplete",
        analysisCount: 0,
        findingCount: 0,
        errorBatchCount: failure === "failed batches" ? 1 : 0,
      };
    });

    await expect(runSetupWorkflow({ ...f.options, signal: controller.signal })).rejects.toThrow(
      failure === "failed batches" ? "1 failed batch" : "Requested pause",
    );
    expect(f.readState().phases.process.status).toBe("error");
    expect(f.readState().processRunId).toBeUndefined();
    expect(f.events).toContainEqual(
      expect.objectContaining({ type: "phase-error", phase: "process" }),
    );
    expect(f.events).not.toContainEqual(
      expect.objectContaining({ type: "phase-complete", phase: "process" }),
    );

    const resumed = await runSetupWorkflow(f.options);
    expect(resumed.processRunId).toBe("process-ok");
    expect(f.processCandidates).toHaveBeenCalledTimes(2);
    expect(f.analyze).toHaveBeenCalledTimes(1);
    expect(f.scan).toHaveBeenCalledTimes(1);
    expect(f.readState().phases.process.status).toBe("complete");
    expect(f.events).toContainEqual(
      expect.objectContaining({ type: "phase-complete", phase: "process" }),
    );
    await runSetupWorkflow(f.options);
    expect(f.processCandidates).toHaveBeenCalledTimes(2);
  });
});

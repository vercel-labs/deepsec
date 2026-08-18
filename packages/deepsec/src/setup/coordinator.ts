import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  dataDir,
  type FileRecord,
  getRegistry,
  loadAllFileRecords,
  writeFileRecord,
} from "@deepsec/core";
import {
  type AgentProgress,
  type ProcessProgress,
  process as processCandidates,
} from "@deepsec/processor";
import {
  createDefaultRegistry,
  type DeclarativeMatcherPlugin,
  type ScanProgress,
  scan,
} from "@deepsec/scanner";
import { buildAgentConfig } from "../agent-config.js";
import { defaultModelForAgent } from "../agent-defaults.js";
import { atomicWriteFileSync } from "../atomic-file.js";
import {
  type ConnectionVerificationCheckpoint,
  ensureConnectedWorkspace,
} from "../auth/ensure-connected-workspace.js";
import type { ModelRoute } from "../auth/model-route.js";
import { loadConfig } from "../load-config.js";
import { resolveAgentType } from "../resolve-agent-type.js";
import {
  type CoverageReport,
  evaluateCoverage,
  expandSurfaceInventory,
  groundSurfaceInventory,
} from "./coverage.js";
import {
  listRepositoryFiles,
  repositoryFingerprint,
  setupRepositoryIgnoreGlobs,
} from "./fingerprint.js";
import {
  proposeGeneratedMatchers,
  readGeneratedMatchers,
  writeGeneratedMatchers,
} from "./generated-matchers.js";
import { ensureWorkspaceInstall, type SupportedPackageManager } from "./install.js";
import { SetupProtocolError } from "./protocol.js";
import { phaseLabel, type SetupReporter } from "./reporter.js";
import {
  analyzeRepository,
  isCompleteInfoMarkdown,
  type RepositoryAnalysis,
  writeRepositoryAnalysis,
} from "./repository-analysis.js";
import {
  completePhase,
  createSetupState,
  digest,
  failPhase,
  isCheckpointCurrent,
  readSetupState,
  type SetupPhase,
  type SetupState,
  setupStatePath,
  startPhase,
  writeSetupState,
} from "./state.js";
import { reconcileWorkspaceConfig } from "./workspace-config.js";

export interface SetupConnectionResult {
  verification: Record<string, unknown>;
  modelAuth?: ModelRoute;
}

export interface SetupWorkflowOptions {
  workspaceDir?: string;
  projectId: string;
  projectRoot: string;
  agent?: string;
  model?: string;
  thinkingLevel?: string;
  modelRoute?: ModelRoute;
  packageManager?: SupportedPackageManager;
  skipInstall?: boolean;
  nonInteractive?: boolean;
  teamId?: string;
  vercelProjectId?: string;
  allowProjectCreate?: boolean;
  vercelProjectName?: string;
  concurrency?: number;
  through?: SetupThrough;
  maxCostUsd?: number;
  maxDurationMs?: number;
  signal?: AbortSignal;
  onLog?: (message: string) => void;
  reporter?: SetupReporter;
  services?: Partial<SetupWorkflowServices>;
}

export interface SetupWorkflowServices {
  install: typeof ensureWorkspaceInstall;
  connect: (
    options: SetupWorkflowOptions,
    previous?: Record<string, unknown>,
  ) => Promise<SetupConnectionResult>;
  analyze: typeof analyzeRepository;
  scan: typeof scan;
  process: typeof processCandidates;
  listFiles: typeof listRepositoryFiles;
  fingerprint: typeof repositoryFingerprint;
  loadRecords: (projectId: string) => FileRecord[];
  proposeMatchers: typeof proposeGeneratedMatchers;
}

export interface SetupWorkflowResult {
  state: SetupState;
  completed: boolean;
  stoppedAfter: SetupThrough;
  coverage?: CoverageReport;
  processRunId?: string;
  process?: {
    analysisCount: number;
    findingCount: number;
    errorBatchCount: number;
    findingsBySeverity: Record<string, number>;
    costUsd: number;
  };
  generatedMatchers: {
    attempts: number;
    accepted: string[];
    rejected: Array<{ slug: string; reason: string }>;
  };
}

export type SetupThrough = "install" | "login" | "threat-model" | "coverage" | "process";

function workflowResult(
  state: SetupState,
  stoppedAfter: SetupThrough,
  coverage?: CoverageReport,
): SetupWorkflowResult {
  return {
    state,
    completed: stoppedAfter === "process",
    stoppedAfter,
    coverage,
    generatedMatchers: {
      attempts: state.matcherAttempts.length,
      accepted: state.matcherAttempts.flatMap((attempt) => attempt.acceptedSlugs),
      rejected: state.matcherAttempts.flatMap((attempt) => attempt.rejected),
    },
  };
}

function infoIsComplete(file: string): boolean {
  if (!fs.existsSync(file)) return false;
  return isCompleteInfoMarkdown(fs.readFileSync(file, "utf8"));
}

function readInventory(file: string): RepositoryAnalysis | undefined {
  if (!fs.existsSync(file)) return undefined;
  try {
    const parsed = JSON.parse(fs.readFileSync(file, "utf8")) as RepositoryAnalysis;
    return Array.isArray(parsed.surfaces) && parsed.surfaces.length > 0 ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function runPhase<T>(
  state: SetupState,
  reporter: SetupReporter,
  phase: SetupPhase,
  inputDigest: string,
  work: () => Promise<T> | T,
  outputDigest: (value: T) => string = (value) => digest(value),
): Promise<T> {
  const startedAt = Date.now();
  reporter.emit({ type: "phase-start", phase, label: phaseLabel(phase) });
  startPhase(state, phase, inputDigest, `${state.projectId}:${phase}:${inputDigest.slice(0, 12)}`);
  return Promise.resolve()
    .then(work)
    .then((value) => {
      completePhase(state, phase, outputDigest(value));
      reporter.emit({ type: "phase-complete", phase, durationMs: Date.now() - startedAt });
      return value;
    })
    .catch((error) => {
      failPhase(state, phase, error);
      reporter.emit({
        type: "phase-error",
        phase,
        message: error instanceof Error ? error.message : String(error),
      });
      throw error;
    });
}

function hitsForSlugs(records: FileRecord[], slugs: string[]): Record<string, string[]> {
  const selected = new Set(slugs);
  const hits: Record<string, Set<string>> = Object.fromEntries(
    slugs.map((slug) => [slug, new Set()]),
  );
  for (const record of records) {
    for (const candidate of record.candidates) {
      if (selected.has(candidate.vulnSlug)) hits[candidate.vulnSlug].add(record.filePath);
    }
  }
  return Object.fromEntries(Object.entries(hits).map(([slug, files]) => [slug, [...files].sort()]));
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function reportAgentProgress(
  reporter: SetupReporter,
  phase: "info" | "matchers",
  progress: AgentProgress,
): void {
  if (progress.type === "tool_use") {
    reporter.emit({ type: "log", phase, level: "info", message: progress.message });
    return;
  }
  if (progress.type === "thinking") {
    reporter.emit({ type: "log", phase, level: "debug", message: progress.message });
    return;
  }
  reporter.emit({ type: "progress", phase, message: progress.message });
}

function reportScanProgress(
  reporter: SetupReporter,
  phase: "baseline-scan" | "final-scan",
  progress: ScanProgress,
): void {
  if (progress.matcherIndex !== undefined && progress.matcherTotal !== undefined) {
    reporter.emit({
      type: "progress",
      phase,
      current: progress.matcherIndex,
      total: progress.matcherTotal,
      message: `Checking ${progress.matcherSlug ?? "matcher"}`,
    });
    return;
  }
  reporter.emit({
    type: "log",
    phase,
    level: progress.type === "file_scanned" && (progress.matchCount ?? 0) > 0 ? "info" : "debug",
    message: progress.message,
  });
}

function reportProcessProgress(reporter: SetupReporter, progress: ProcessProgress): void {
  const current = progress.batchIndex === undefined ? undefined : progress.batchIndex + 1;
  if (progress.type === "agent_progress" && progress.agentProgress?.type === "tool_use") {
    reporter.emit({ type: "log", phase: "process", level: "info", message: progress.message });
    return;
  }
  if (progress.type === "agent_progress" && progress.agentProgress?.type === "thinking") {
    reporter.emit({ type: "log", phase: "process", level: "debug", message: progress.message });
    return;
  }
  reporter.emit({
    type: "progress",
    phase: "process",
    current,
    total: progress.totalBatches,
    message: progress.message,
  });
}

function previousConnection(state: SetupState): Record<string, unknown> | undefined {
  return state.connection && typeof state.connection === "object" ? state.connection : undefined;
}

function installFingerprint(workspaceDir: string): string {
  const manifest = fs.readFileSync(path.join(workspaceDir, "package.json"), "utf8");
  let localArtifacts: string | undefined;
  try {
    const dependency = JSON.parse(manifest).dependencies?.deepsec;
    if (typeof dependency === "string" && dependency.startsWith("file:")) {
      const packageRoot = fileURLToPath(dependency);
      localArtifacts = digest(
        ["dist/cli.mjs", "dist/config.mjs"].map((relative) =>
          fs.readFileSync(path.join(packageRoot, relative)),
        ),
      );
    }
  } catch {
    // Installation reports malformed manifests or missing local artifacts with
    // its normal actionable error; the manifest still invalidates the phase.
  }
  return digest({ manifest, localArtifacts });
}

export async function runSetupWorkflow(
  options: SetupWorkflowOptions,
): Promise<SetupWorkflowResult> {
  const workspaceDir = path.resolve(options.workspaceDir ?? process.cwd());
  const projectRoot = path.resolve(options.projectRoot);
  const fallbackLog = options.onLog ?? console.log;
  const reporter: SetupReporter =
    options.reporter ??
    ({
      interactive: false,
      emit(event) {
        if (event.type === "phase-start") fallbackLog(event.label);
        if (event.type === "phase-skip") fallbackLog(`✓ ${event.reason}`);
        if (event.type === "log" && event.level !== "debug") fallbackLog(event.message);
      },
      async suspend(work) {
        return await work();
      },
      async close() {},
    } satisfies SetupReporter);
  const log = (message: string, phase?: SetupPhase, level: "debug" | "info" | "warn" = "info") =>
    reporter.emit({ type: "log", phase, level, message });
  const services: SetupWorkflowServices = {
    install: ensureWorkspaceInstall,
    connect: async (setupOptions, previous) => {
      const agentType = resolveAgentType(setupOptions.agent);
      const result = await ensureConnectedWorkspace({
        workspaceDir,
        interactive: !setupOptions.nonInteractive,
        modelRoute: setupOptions.modelRoute ?? { mode: "gateway", provider: "vercel" },
        agentTypes: [agentType],
        env: process.env,
        teamId: setupOptions.teamId,
        projectId: setupOptions.vercelProjectId,
        allowCreate: setupOptions.allowProjectCreate,
        projectName: setupOptions.vercelProjectName,
        previous: previous as unknown as ConnectionVerificationCheckpoint | undefined,
        onLog: (message) => log(message, "login"),
        dependencies: {},
      });
      return {
        verification: result.verification as unknown as Record<string, unknown>,
        modelAuth: result.modelAuth,
      };
    },
    analyze: analyzeRepository,
    scan,
    process: processCandidates,
    listFiles: listRepositoryFiles,
    fingerprint: repositoryFingerprint,
    loadRecords: loadAllFileRecords,
    proposeMatchers: proposeGeneratedMatchers,
    ...options.services,
  };

  const durationController = new AbortController();
  const durationTimer =
    options.maxDurationMs !== undefined
      ? setTimeout(() => durationController.abort(), options.maxDurationMs)
      : undefined;
  durationTimer?.unref();
  const workflowSignal = options.signal
    ? AbortSignal.any([options.signal, durationController.signal])
    : durationController.signal;
  const durationLimitError = () =>
    new SetupProtocolError({
      code: "DURATION_LIMIT_REACHED",
      kind: "limit",
      message: `Setup reached its ${options.maxDurationMs}ms duration limit and stopped at a resumable checkpoint.`,
      details: { maxDurationMs: options.maxDurationMs },
    });
  const assertWithinDuration = () => {
    if (durationController.signal.aborted) throw durationLimitError();
  };

  const originalCwd = process.cwd();
  process.chdir(workspaceDir);
  try {
    const existingState = readSetupState(options.projectId);
    const agentType = resolveAgentType(options.agent ?? existingState?.agent.type);
    const previousModel =
      existingState?.agent.type === agentType ? existingState.agent.model : undefined;
    const model = options.model ?? previousModel ?? defaultModelForAgent(agentType);
    const thinkingLevel = options.thinkingLevel ?? existingState?.agent.thinkingLevel;
    const state =
      existingState ??
      createSetupState({
        projectId: options.projectId,
        targetRoot: projectRoot,
        agentType,
        model,
        thinkingLevel,
      });
    state.agent = { type: agentType, model, ...(thinkingLevel ? { thinkingLevel } : {}) };
    if (reporter.logPath) {
      state.setupLogPath = path.relative(workspaceDir, reporter.logPath).replaceAll(path.sep, "/");
      writeSetupState(state);
    }

    const scaffoldInput = digest({ workspaceDir, projectRoot, projectId: options.projectId });
    if (!isCheckpointCurrent(state, "scaffold", scaffoldInput)) {
      await runPhase(state, reporter, "scaffold", scaffoldInput, () => true);
    } else {
      reporter.emit({ type: "phase-skip", phase: "scaffold", reason: "workspace is current" });
    }

    const installInput = installFingerprint(workspaceDir);
    let installResult: Awaited<ReturnType<typeof ensureWorkspaceInstall>>;
    if (
      !isCheckpointCurrent(state, "install", installInput, () =>
        fs.existsSync("node_modules/deepsec"),
      )
    ) {
      installResult = await runPhase(state, reporter, "install", installInput, () =>
        services.install({
          workspaceDir,
          packageManager: options.packageManager,
          skipInstall: options.skipInstall,
          force: true,
          onOutput: (line, stream) => log(`${stream}: ${line}`, "install", "debug"),
          onProgress: (progress) =>
            reporter.emit({ type: "progress", phase: "install", ...progress }),
        }),
      );
    } else {
      // Re-run the cheap probe so a deleted/corrupt node_modules cannot hide behind state.
      installResult = await services.install({
        workspaceDir,
        packageManager: options.packageManager,
        skipInstall: options.skipInstall,
        quiet: true,
      });
      reporter.emit({ type: "phase-skip", phase: "install", reason: "install is current" });
    }
    assertWithinDuration();
    if (options.through === "install") return workflowResult(state, "install");

    const checkpointRoute = (state.connection as { route?: ModelRoute } | undefined)?.route;
    const existingConfig =
      !options.modelRoute && !checkpointRoute ? await loadConfig(workspaceDir) : undefined;
    const route = options.modelRoute ??
      checkpointRoute ??
      (existingConfig?.config.ai as ModelRoute | undefined) ?? {
        mode: "gateway",
        provider: "vercel",
      };
    const agentConfig = buildAgentConfig({ model, thinkingLevel, modelRoute: route });
    reconcileWorkspaceConfig(workspaceDir, route, agentType, model, thinkingLevel);

    const loaded = await loadConfig(workspaceDir);
    if (!loaded) throw new Error(`Could not load ${path.join(workspaceDir, "deepsec.config.ts")}`);

    const loginInput = digest({
      route,
      agentType,
      teamId: options.teamId,
      projectId: options.vercelProjectId,
    });
    if (!isCheckpointCurrent(state, "login", loginInput)) {
      const connected = await runPhase(state, reporter, "login", loginInput, () =>
        reporter.suspend(() =>
          services.connect({ ...options, modelRoute: route }, previousConnection(state)),
        ),
      );
      state.connection = connected.verification;
      writeSetupState(state);
    } else {
      // Rehydrate credentials every process; the auth layer reuses the fresh verification checkpoint.
      const connected = await reporter.suspend(() =>
        services.connect({ ...options, modelRoute: route }, previousConnection(state)),
      );
      state.connection = connected.verification;
      writeSetupState(state);
      reporter.emit({
        type: "phase-skip",
        phase: "login",
        reason: "Vercel link and model access are current",
      });
    }
    assertWithinDuration();
    if (options.through === "login") return workflowResult(state, "login");

    const repositoryIgnoreGlobs = setupRepositoryIgnoreGlobs(projectRoot, workspaceDir);
    const repositoryFiles = services.listFiles(projectRoot, repositoryIgnoreGlobs);
    const sourceFingerprint = services.fingerprint(projectRoot, repositoryFiles);
    state.sourceFingerprint = sourceFingerprint;
    const projectDataDir = path.resolve(dataDir(options.projectId));
    const infoPath = path.join(projectDataDir, "INFO.md");
    const inventoryPath = path.join(projectDataDir, "setup", "surface-inventory.json");
    let analysis = readInventory(inventoryPath);
    const infoInput = digest({
      projectRoot,
      sourceFingerprint,
      agentType,
      model,
      thinkingLevel,
      rubricVersion: 2,
    });
    if (
      !analysis ||
      !infoIsComplete(infoPath) ||
      !isCheckpointCurrent(state, "info", infoInput, () =>
        Boolean(readInventory(inventoryPath) && infoIsComplete(infoPath)),
      )
    ) {
      const preserveInfo = infoIsComplete(infoPath) ? fs.readFileSync(infoPath, "utf8") : undefined;
      analysis = await runPhase(state, reporter, "info", infoInput, () =>
        services.analyze({
          projectId: options.projectId,
          projectRoot,
          agentType,
          agentConfig,
          signal: workflowSignal,
          onProgress: (progress) => reportAgentProgress(reporter, "info", progress),
        }),
      );
      writeRepositoryAnalysis(projectDataDir, analysis);
      if (preserveInfo) atomicWriteFileSync(infoPath, preserveInfo);
      state.infoDigest = digest(fs.readFileSync(infoPath, "utf8"));
      state.inventoryDigest = digest(analysis.surfaces);
      writeSetupState(state);
    } else {
      reporter.emit({
        type: "phase-skip",
        phase: "info",
        reason: "threat model and inventory are current",
      });
    }
    assertWithinDuration();

    const inventoryOptions = { ignoreGlobs: repositoryIgnoreGlobs };
    const grounded = groundSurfaceInventory(analysis.surfaces, repositoryFiles, inventoryOptions);
    if (grounded.issues.length > 0) {
      throw new Error(
        `Surface inventory is invalid: ${grounded.issues.map((issue) => `${issue.itemId ?? issue.itemIndex}.${issue.field}: ${issue.message}`).join("; ")}`,
      );
    }
    if (grounded.changes.length > 0) {
      analysis = {
        ...analysis,
        infoMarkdown: fs.readFileSync(infoPath, "utf8").trim(),
        surfaces: grounded.inventory,
      };
      writeRepositoryAnalysis(projectDataDir, analysis);
      state.inventoryDigest = digest(analysis.surfaces);
      writeSetupState(state);
    }
    const expanded = expandSurfaceInventory(grounded.inventory, repositoryFiles, inventoryOptions);
    if (expanded.issues.length > 0) {
      throw new Error(
        `Surface inventory is invalid: ${expanded.issues.map((issue) => `${issue.itemId ?? issue.itemIndex}.${issue.field}: ${issue.message}`).join("; ")}`,
      );
    }
    if (options.through === "threat-model") {
      return workflowResult(state, "threat-model");
    }

    let generated: DeclarativeMatcherPlugin[] = readGeneratedMatchers(workspaceDir);
    const configuredMatcherDigest = digest(generated.map((matcher) => matcher.declarativeSpec));
    const baselineInput = digest({ sourceFingerprint, matcherDigest: configuredMatcherDigest });
    let baselineResult: Awaited<ReturnType<typeof scan>>;
    if (!isCheckpointCurrent(state, "baseline-scan", baselineInput) || !state.baselineScanSummary) {
      baselineResult = await runPhase(state, reporter, "baseline-scan", baselineInput, () =>
        services.scan({
          projectId: options.projectId,
          root: projectRoot,
          onProgress: (progress) => reportScanProgress(reporter, "baseline-scan", progress),
        }),
      );
      state.baselineScanRunId = baselineResult.runId;
      state.baselineScanSummary = {
        runId: baselineResult.runId,
        languageStats: baselineResult.languageStats,
      };
      state.finalScanRunId = undefined;
      state.finalScanSummary = undefined;
      state.matcherDigest = configuredMatcherDigest;
      writeSetupState(state);
    } else {
      const activeScanSummary = state.finalScanSummary ?? state.baselineScanSummary;
      baselineResult = {
        runId: activeScanSummary.runId,
        candidateCount: 0,
        detected: { tags: [], sentinels: [], detectedAt: "", rootPath: projectRoot },
        activeMatchers: [],
        skippedMatchers: [],
        languageStats: activeScanSummary.languageStats,
      };
      reporter.emit({
        type: "phase-skip",
        phase: "baseline-scan",
        reason: "baseline scan is current",
      });
    }

    let records = services.loadRecords(options.projectId);
    let coverage = evaluateCoverage({
      inventory: expanded.items,
      sourceFiles: expanded.sourceFiles,
      candidateRecords: records,
      scanResult: baselineResult,
    });
    const coverageInput = digest({ runId: baselineResult.runId, inventory: state.inventoryDigest });
    await runPhase(state, reporter, "coverage", coverageInput, () => coverage);
    reporter.emit({
      type: "metrics",
      phase: "coverage",
      values: {
        "source files": coverage.sourceFileCount,
        "candidate files": coverage.candidateFileCount,
        surfaces: coverage.surfaces.length,
        "uncovered surfaces": coverage.surfaces.filter((surface) => !surface.passed).length,
      },
    });
    state.coverageReport = coverage;
    writeSetupState(state);

    const maxAttempts = 2;
    for (let attempt = 0; !coverage.passed && attempt < maxAttempts; attempt++) {
      reporter.emit({
        type: "progress",
        phase: "matchers",
        current: attempt + 1,
        total: maxAttempts,
        message: `Generating project-specific matchers (attempt ${attempt + 1}/${maxAttempts})`,
      });
      const existingSlugs = [
        ...createDefaultRegistry()
          .getAll()
          .map((matcher) => matcher.slug),
        ...getRegistry().matchers.map((matcher) => matcher.slug),
        ...services
          .loadRecords(options.projectId)
          .flatMap((record) => record.candidates.map((candidate) => candidate.vulnSlug)),
        ...generated.map((matcher) => matcher.slug),
      ];
      const proposal = await runPhase(
        state,
        reporter,
        "matchers",
        digest({ coverage, attempt }),
        () =>
          services.proposeMatchers({
            projectRoot,
            agentType,
            agentConfig,
            inventory: expanded.items,
            coverage,
            existingSlugs: [...new Set(existingSlugs)],
            signal: workflowSignal,
            onProgress: (progress) => reportAgentProgress(reporter, "matchers", progress),
          }),
      );
      if (proposal.plugins.length === 0) {
        state.matcherAttempts.push({
          proposedSlugs: [],
          proposedSpecs: [],
          acceptedSlugs: [],
          rejected: [],
          outcome: "empty-proposal",
        });
        writeSetupState(state);
        continue;
      }
      generated.push(...proposal.plugins);
      writeGeneratedMatchers(
        workspaceDir,
        generated.map((matcher) => matcher.declarativeSpec),
      );
      getRegistry().matchers.push(...proposal.plugins);

      const finalResult = await runPhase(
        state,
        reporter,
        "final-scan",
        digest({ sourceFingerprint, slugs: generated.map((m) => m.slug) }),
        () =>
          services.scan({
            projectId: options.projectId,
            root: projectRoot,
            onProgress: (progress) => reportScanProgress(reporter, "final-scan", progress),
          }),
      );
      state.finalScanRunId = finalResult.runId;
      state.finalScanSummary = {
        runId: finalResult.runId,
        languageStats: finalResult.languageStats,
      };
      records = services.loadRecords(options.projectId);
      coverage = evaluateCoverage({
        inventory: expanded.items,
        sourceFiles: expanded.sourceFiles,
        candidateRecords: records,
        scanResult: finalResult,
        newMatcherHits: hitsForSlugs(
          records,
          proposal.plugins.map((matcher) => matcher.slug),
        ),
      });
      const exploding = new Set(coverage.explosionWarnings.map((warning) => warning.matcherSlug));
      const explosionReasons = new Map(
        coverage.explosionWarnings.map((warning) => [warning.matcherSlug, warning.reason]),
      );
      if (exploding.size > 0) {
        generated = generated.filter((matcher) => !exploding.has(matcher.slug));
        getRegistry().matchers = getRegistry().matchers.filter(
          (matcher) => !exploding.has(matcher.slug),
        );
        for (const record of records) {
          const candidates = record.candidates.filter(
            (candidate) => !exploding.has(candidate.vulnSlug),
          );
          if (candidates.length !== record.candidates.length) {
            record.candidates = candidates;
            writeFileRecord(record);
          }
        }
        writeGeneratedMatchers(
          workspaceDir,
          generated.map((matcher) => matcher.declarativeSpec),
        );
        records = services.loadRecords(options.projectId);
        coverage = evaluateCoverage({
          inventory: expanded.items,
          sourceFiles: expanded.sourceFiles,
          candidateRecords: records,
          scanResult: finalResult,
        });
      }
      state.matcherAttempts.push({
        proposedSlugs: proposal.plugins.map((matcher) => matcher.slug),
        proposedSpecs: proposal.specs,
        acceptedSlugs: proposal.plugins
          .map((matcher) => matcher.slug)
          .filter((slug) => !exploding.has(slug)),
        rejected: [...exploding].map((slug) => ({
          slug,
          reason:
            explosionReasons.get(slug) ?? "generated matcher exceeded the configured breadth limit",
        })),
        outcome: "rescanned",
        scanRunId: finalResult.runId,
      });
      state.matcherDigest = digest(generated.map((matcher) => matcher.declarativeSpec));
      state.coverageReport = coverage;
      writeSetupState(state);
    }

    if (!coverage.passed) {
      const noCandidates = coverage.candidateFileCount === 0;
      const recentAttempts = state.matcherAttempts.slice(-maxAttempts);
      const firstAttemptNumber = state.matcherAttempts.length - recentAttempts.length + 1;
      const matcherOutcome = recentAttempts
        .map((attempt, index) => {
          const label = `attempt ${firstAttemptNumber + index}`;
          if (attempt.outcome === "empty-proposal" || attempt.proposedSlugs.length === 0) {
            return `${label} returned no matcher proposals`;
          }
          const accepted =
            attempt.acceptedSlugs.length > 0
              ? `accepted ${attempt.acceptedSlugs.join(", ")}`
              : undefined;
          const rejected =
            attempt.rejected.length > 0
              ? `rejected ${attempt.rejected.map(({ slug, reason }) => `${slug} (${reason})`).join(", ")}`
              : undefined;
          return `${label} ${[accepted, rejected].filter(Boolean).join("; ") || "did not improve coverage"}`;
        })
        .join("; ");
      const stateFile = setupStatePath(options.projectId);
      const generatedMatchersFile = path.join(workspaceDir, "generated-matchers.ts");
      const setupLogFile = state.setupLogPath
        ? path.resolve(workspaceDir, state.setupLogPath)
        : undefined;
      const setupInvocation =
        installResult.packageManager === "npm"
          ? `npm run deepsec -- setup --project-id ${shellQuote(options.projectId)}`
          : `pnpm deepsec setup --project-id ${shellQuote(options.projectId)}`;
      const resumeCommand = `cd ${shellQuote(workspaceDir)} && ${setupInvocation}`;
      const code = noCandidates ? "NO_SCAN_CANDIDATES" : "SCAN_COVERAGE_INSUFFICIENT";
      const error = new SetupProtocolError({
        code,
        message: noCandidates
          ? `Setup paused before AI processing because the scan produced no candidates for the inventoried surfaces: ${coverage.reasons.join("; ")}. Matcher repair: ${matcherOutcome || "no attempts completed"}. This checkpoint is safe to resume.`
          : `Setup paused before AI processing because scan coverage is insufficient: ${coverage.reasons.join("; ")}. Matcher repair: ${matcherOutcome || "no attempts completed"}. This checkpoint is safe to resume.`,
        missingInputs: ["scan.coverage"],
        actions: [
          {
            id: "inspect-scan-coverage",
            description:
              "Inspect the uncovered surfaces, exact matcher proposals, and rejection reasons.",
            commands: [
              `cat ${shellQuote(inventoryPath)}`,
              `cat ${shellQuote(stateFile)}`,
              `cat ${shellQuote(generatedMatchersFile)}`,
            ],
          },
          {
            id: "retry-matcher-repair",
            description:
              "Resume setup to retry up to two automated matcher proposals after reviewing or editing generated-matchers.ts.",
            commands: [resumeCommand],
          },
        ],
        details: {
          coverage,
          matcherAttempts: recentAttempts,
          recovery: {
            resumable: true,
            resumeCommand,
            files: {
              surfaceInventory: inventoryPath,
              setupState: stateFile,
              generatedMatchers: generatedMatchersFile,
              ...(setupLogFile ? { setupLog: setupLogFile } : {}),
            },
          },
        },
      });
      state.lastError = {
        phase: "coverage",
        code,
        message: error.message,
        at: new Date().toISOString(),
      };
      writeSetupState(state);
      throw error;
    }
    assertWithinDuration();
    if (options.through === "coverage") return workflowResult(state, "coverage", coverage);

    const processInput = digest({
      sourceFingerprint,
      scanRunId: state.finalScanRunId ?? state.baselineScanRunId,
      agentType,
      model,
      thinkingLevel,
    });
    let processResult: Awaited<ReturnType<typeof processCandidates>>;
    if (!isCheckpointCurrent(state, "process", processInput) || !state.processRunId) {
      processResult = await runPhase(state, reporter, "process", processInput, async () => {
        const result = await services.process({
          projectId: options.projectId,
          agentType,
          config: agentConfig,
          concurrency: options.concurrency,
          signal: workflowSignal,
          maxCostUsd: options.maxCostUsd,
          onProgress: (progress) => reportProcessProgress(reporter, progress),
        });
        if (durationController.signal.aborted) throw durationLimitError();
        if (result.costLimitReached) {
          throw new SetupProtocolError({
            code: "COST_LIMIT_REACHED",
            kind: "limit",
            message: `AI investigation reached the $${result.costLimitReached.limitUsd.toFixed(2)} cost limit and stopped at a resumable checkpoint.`,
            details: result.costLimitReached,
          });
        }
        return result;
      });
      state.processRunId = processResult.runId;
      writeSetupState(state);
    } else {
      processResult = {
        runId: state.processRunId,
        analysisCount: 0,
        findingCount: 0,
        errorBatchCount: 0,
      };
      reporter.emit({
        type: "phase-skip",
        phase: "process",
        reason: "AI investigation is current",
      });
    }

    if (processResult.errorBatchCount > 0) {
      throw new Error(
        `AI processing completed with ${processResult.errorBatchCount} failed batch(es)`,
      );
    }
    const completedRecords = services.loadRecords(options.projectId);
    const completedHistory = completedRecords.flatMap((record) =>
      record.analysisHistory.filter((entry) => entry.runId === processResult.runId),
    );
    const completedFindings = completedRecords.flatMap((record) =>
      record.findings.filter((finding) => finding.producedByRunId === processResult.runId),
    );
    const findingsBySeverity = Object.fromEntries(
      completedFindings.reduce((counts, finding) => {
        counts.set(finding.severity, (counts.get(finding.severity) ?? 0) + 1);
        return counts;
      }, new Map<string, number>()),
    );
    return {
      ...workflowResult(state, "process", coverage),
      processRunId: processResult.runId,
      process: {
        analysisCount: completedHistory.length || processResult.analysisCount,
        findingCount: completedFindings.length || processResult.findingCount,
        errorBatchCount: processResult.errorBatchCount,
        findingsBySeverity,
        costUsd: completedHistory.reduce((total, entry) => total + (entry.costUsd ?? 0), 0),
      },
    };
  } catch (error) {
    if (durationController.signal.aborted && !(error instanceof SetupProtocolError)) {
      throw durationLimitError();
    }
    throw error;
  } finally {
    if (durationTimer) clearTimeout(durationTimer);
    process.chdir(originalCwd);
  }
}

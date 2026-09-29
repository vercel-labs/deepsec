import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { FileRecord, Severity } from "@deepsec/core";
import {
  acquireProcessLock,
  completeRun,
  createRunMeta,
  dataDir,
  defaultConcurrency,
  ensureFindingIds,
  getRegistry,
  isPidAlive,
  loadAllFileRecords,
  readFileRecord,
  readProjectConfig,
  readRunMeta,
  registerActiveRun,
  writeFileRecord,
  writeRunMeta,
} from "@deepsec/core";
import { noiseScore, readTechJson } from "@deepsec/scanner";
import { ClaudeAgentSdkPlugin } from "./agents/claude-agent-sdk.js";
import { CodexAgentSdkPlugin } from "./agents/codex-sdk.js";
import { GrokBuildAgentPlugin } from "./agents/grok-build.js";
import { PiAgentPlugin } from "./agents/pi-sdk.js";
import { AgentRegistry } from "./agents/registry.js";
import { QuotaExhaustedError, type QuotaSource } from "./agents/shared.js";
import type {
  AgentPlugin,
  AgentProgress,
  InvestigateOutput,
  RevalidateOutput,
} from "./agents/types.js";
import { batchCandidates } from "./batch.js";
import { enrichFileRecord } from "./enrich.js";
import { assemblePrompt } from "./prompt/assemble.js";
import { languagesForBatch } from "./prompt/file-language.js";
import {
  buildAliasMap,
  type ExpectedFinding,
  expectedFindingsForBatch,
  reconcileVerdicts,
  resolveDuplicateRef,
} from "./reconcile.js";

export { ClaudeAgentSdkPlugin } from "./agents/claude-agent-sdk.js";
export { CodexAgentSdkPlugin } from "./agents/codex-sdk.js";
export { GrokBuildAgentPlugin } from "./agents/grok-build.js";
export { PiAgentPlugin } from "./agents/pi-sdk.js";
export { AgentRegistry } from "./agents/registry.js";
export {
  attributionHeaders,
  classifyQuotaError,
  isGatewayBaseUrl,
  isUsingAiGateway,
  type QuotaAgentHint,
  QuotaExhaustedError,
  type QuotaSource,
  setAttributionVersion,
} from "./agents/shared.js";
export type { AgentPlugin, AgentProgress } from "./agents/types.js";
export { batchCandidates } from "./batch.js";
export { enrich } from "./enrich.js";
export type { AssembleParams, AssembleResult, TechHighlight } from "./prompt/index.js";
export {
  assemblePrompt,
  CORE_PROMPT,
  highlightForTag,
  noteForSlug,
  TECH_HIGHLIGHTS,
} from "./prompt/index.js";
export {
  buildAliasMap,
  type ExpectedFinding,
  expectedFindingsForBatch,
  type MatchedBy,
  normalizeAliasRef,
  normalizePath,
  normalizeTitle,
  type ReconcileDiagnostic,
  type ReconcileMatch,
  type ReconcileResult,
  reconcileVerdicts,
  resolveDuplicateRef,
} from "./reconcile.js";
export { type RunSetupTaskParams, runSetupTask } from "./setup-agent.js";
export { triage } from "./triage.js";

export function createDefaultAgentRegistry(): AgentRegistry {
  const registry = new AgentRegistry();
  registry.register(new ClaudeAgentSdkPlugin());
  registry.register(new CodexAgentSdkPlugin());
  registry.register(new PiAgentPlugin());
  registry.register(new GrokBuildAgentPlugin());
  // Plugins can contribute additional backends via `agents: []` in their
  // DeepsecPlugin export. The shape is validated by AgentRegistry at use.
  for (const a of getRegistry().agents as AgentPlugin[]) {
    registry.register(a);
  }
  return registry;
}

export interface ProcessProgress {
  type: "batch_started" | "batch_complete" | "agent_progress" | "all_complete";
  message: string;
  batchIndex?: number;
  totalBatches?: number;
  agentProgress?: AgentProgress;
}

export async function process(params: {
  projectId: string;
  runId?: string;
  agentType?: string;
  config?: Record<string, unknown>;
  promptTemplate?: string;
  /**
   * `true` — always re-investigate every file regardless of history.
   * `number` — wave marker. Process files that don't yet have a productive
   *   analysis by the current agent tagged with this marker. Re-running
   *   the same N is idempotent (skips already-done files); bump N to
   *   request another pass. Different agents get distinct marker spaces.
   * `false`/undefined — default: only pending/error files.
   */
  reinvestigate?: boolean | number;
  /** Max number of files to process in this run */
  limit?: number;
  /** Number of batches to process concurrently (default: 1) */
  concurrency?: number;
  /** Only process files matching this path prefix */
  filter?: string;
  /** Files per batch (default: 5) */
  batchSize?: number;
  /** Override rootPath from project.json (for sandbox execution) */
  rootPathOverride?: string;
  /** Path to JSON manifest file listing exact file paths to process */
  manifestPath?: string;
  /** Only process files that have at least one candidate slug in this set */
  onlySlugs?: string[];
  /** Skip files whose candidate slugs are ALL in this set (files with any other slug still get processed) */
  skipSlugs?: string[];
  /**
   * Direct invocation mode. When set, the scanner-state filter
   * (pending/error/stale) is bypassed and these exact files are always
   * investigated — regardless of prior status. Used by `process --diff`
   * and friends. Caller is expected to have run `scanFiles()` first so
   * each path has a FileRecord on disk; missing records are skipped
   * with a console warning.
   */
  filePaths?: string[];
  /** Free-form origin label for direct invocations (e.g. "git-diff:origin/main"). */
  source?: string;
  /** Cancel in-flight agent work and stop claiming new batches. */
  signal?: AbortSignal;
  onProgress?: (progress: ProcessProgress) => void;
  /** Stop claiming new batches once completed batch cost reaches this limit. */
  maxCostUsd?: number;
}): Promise<{
  runId: string;
  analysisCount: number;
  findingCount: number;
  /**
   * Batches whose agent threw — i.e. produced no usable result text after
   * retries. Distinct from a clean run with zero findings: a non-zero
   * count means the agent failed to run (missing binary, gateway error,
   * crashed CLI). CI gates on this so a silent fail doesn't pass.
   */
  errorBatchCount: number;
  /**
   * Set when one of the batches threw `QuotaExhaustedError`. Once any
   * batch hits this, every subsequent API call against the same credential
   * will fail the same way, so the processor aborts in-flight batches and
   * stops launching new ones. The CLI uses `quotaExhausted` to print a
   * remediation message tailored to the source (subscription / direct
   * provider / gateway).
   */
  quotaExhausted?: { source: QuotaSource; rawMessage: string };
  totalCostUsd?: number;
  costLimitReached?: { limitUsd: number; actualUsd: number };
}> {
  const { projectId, agentType = "claude-agent-sdk", config = {}, reinvestigate = false } = params;
  // We deliberately don't default `promptTemplate` to DEFAULT_PROMPT_TEMPLATE
  // here — when the caller doesn't pass one, we use the modular assembler
  // so the prompt can adapt to the detected tech stack on a per-batch
  // basis. Callers that pass an explicit promptTemplate (e.g. from
  // `--prompt-template`) get that string verbatim, no assembly.
  const customPromptTemplate = params.promptTemplate;

  // Wrap progress callback so it never crashes the processor
  const emitProgress = (progress: ProcessProgress) => {
    try {
      params.onProgress?.(progress);
    } catch (err) {
      console.error(
        `[deepsec] progress callback error: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  };

  const project = readProjectConfig(projectId);
  const effectiveRootPath = params.rootPathOverride
    ? path.resolve(params.rootPathOverride)
    : project.rootPath;

  if (!fs.existsSync(effectiveRootPath)) {
    const source = params.rootPathOverride ? "--root" : `data/${projectId}/project.json:rootPath`;
    throw new Error(
      `Project root does not exist: ${effectiveRootPath}\n` +
        `  (came from ${source})\n` +
        `  Re-scan with the correct path: deepsec scan --project-id ${projectId} --root <correct-path>`,
    );
  }

  // Load manifest if provided
  let manifestFilePaths: Set<string> | undefined;
  if (params.manifestPath) {
    const raw = JSON.parse(fs.readFileSync(params.manifestPath, "utf-8"));
    if (!Array.isArray(raw)) throw new Error("Manifest must be a JSON array of file paths");
    manifestFilePaths = new Set(raw as string[]);
  }

  // Load project INFO.md if it exists
  const infoPath = path.join(dataDir(projectId), "INFO.md");
  let projectInfo = "";
  try {
    projectInfo = fs.readFileSync(infoPath, "utf-8");
  } catch {
    // No INFO.md — that's fine
  }

  // Load project config.json for prompt customization and priority
  const projectConfigJsonPath = path.join(dataDir(projectId), "config.json");
  let projectConfig: {
    priorityPaths?: string[];
    promptAppend?: string;
  } = {};
  try {
    projectConfig = JSON.parse(fs.readFileSync(projectConfigJsonPath, "utf-8"));
  } catch {
    // No config.json — that's fine
  }

  // Tech detection result drives per-batch threat highlights. Read once
  // from `data/<id>/tech.json` (written by `scan()`); empty list when the
  // project predates tech detection — assembler then falls back to bare
  // core prompt, which matches the legacy DEFAULT_PROMPT_TEMPLATE shape.
  const techDetected = readTechJson(projectId);
  const detectedTags = techDetected?.tags ?? [];

  /**
   * Build the prompt for a specific batch. Two paths:
   *   - Caller passed an explicit promptTemplate → use it verbatim
   *     (with the existing project-config promptAppend behavior). This
   *     keeps `--prompt-template` callers working unchanged.
   *   - Otherwise → assemble per-batch from core + tech highlights +
   *     batch-slug notes, so the prompt adapts to what we detected.
   */
  const buildBatchPrompt = (batch: FileRecord[]): string => {
    if (customPromptTemplate !== undefined) {
      let p = customPromptTemplate;
      if (projectConfig.promptAppend) {
        p += "\n" + projectConfig.promptAppend;
      }
      return p;
    }
    const batchSlugs = Array.from(
      new Set(batch.flatMap((r) => r.candidates.map((c) => c.vulnSlug))),
    );
    // Per-batch tech filtering: keep only the highlights whose language
    // matches a file in this specific batch. A batch of pure Python
    // files in a polyglot Next.js + Django repo gets the Django pack
    // but not the Next.js pack, even though both are project-level
    // detected tags.
    const batchLanguages = languagesForBatch(batch.map((r) => r.filePath));
    const { prompt } = assemblePrompt({
      detectedTags,
      batchSlugs,
      batchLanguages,
      projectInfo,
      promptAppend: projectConfig.promptAppend,
    });
    return prompt;
  };

  const model = (config.model as string) ?? "claude-opus-4-8";

  // Create or resume run
  let runId: string;
  if (params.runId) {
    // Resume existing run
    runId = params.runId;
    const existing = readRunMeta(projectId, runId);
    if (existing.phase === "done") {
      emitProgress({
        type: "all_complete",
        message: `Run ${runId} already completed`,
      });
      return { runId, analysisCount: 0, findingCount: 0, errorBatchCount: 0 };
    }
  } else {
    // Create new run
    const directMode = params.filePaths !== undefined;
    const meta = createRunMeta({
      projectId,
      rootPath: effectiveRootPath,
      type: "process",
      processorConfig: {
        agentType,
        model,
        modelConfig: config,
        invocationMode: directMode ? "direct" : "scan",
        source: directMode ? params.source : undefined,
      },
    });
    writeRunMeta(meta);
    runId = meta.runId;
  }

  // Catch SIGINT/SIGTERM and any thrown error path: flip the run's
  // phase to "error" so its locks become immediately reclaimable by
  // the next invocation instead of waiting out STALE_LOCK_MS (1h).
  // Hard kills (SIGKILL/OOM/power) bypass this; those are handled by
  // the PID-liveness branch in isReclaimableLock.
  const unregisterRun = registerActiveRun(projectId, runId);

  try {
    const registry = createDefaultAgentRegistry();
    const maybeAgent = registry.get(agentType);
    if (!maybeAgent) {
      throw new Error(
        `Unknown agent type: ${agentType}. Available: ${registry.types().join(", ")}`,
      );
    }
    const agent = maybeAgent;

    // Reclaim policy for `processing` records held by other runs. The
    // race we're protecting against: two `process()` invocations against
    // the same project at the same time. Without this check, the second
    // run grabs files the first run is mid-investigation on, both write
    // back, and findings/history get clobbered.
    //
    // A lock is reclaimable when ANY of:
    //   1. The owning run's RunMeta says it's done/error/missing — the
    //      lock won't be released by the original owner, ever. Covers the
    //      graceful-shutdown path (SIGINT/SIGTERM) where we proactively
    //      flip the run to `error` before exiting.
    //   2. The owning run was started on this host and its PID is no
    //      longer alive — the run crashed (SIGKILL / OOM / power loss)
    //      without flipping phase. PID liveness gives us instant recovery
    //      instead of waiting out STALE_LOCK_MS.
    //   3. The lock is older than STALE_LOCK_MS — backstop for cross-host
    //      stale runs and any case where neither phase nor PID tell us.
    //
    // STALE_LOCK_MS is generous (1h) because individual investigations
    // can legitimately take 20–40 minutes on big repos with max
    // thinking. False reclaims are catastrophic; false rejections only
    // cost a retry on the next run.
    const STALE_LOCK_MS = 60 * 60 * 1000;
    const localHostname = os.hostname();
    const isReclaimableLock = (r: FileRecord): boolean => {
      if (!r.lockedByRunId) return true;
      // Cross-check the owning run's status. A done/error/missing run's
      // lock is always safe to reclaim — nobody is going to flip the
      // record back to "analyzed".
      let ownerMeta: Awaited<ReturnType<typeof readRunMeta>> | undefined;
      try {
        ownerMeta = readRunMeta(projectId, r.lockedByRunId);
      } catch {
        // Missing/corrupt run-meta — owning run is gone, reclaim safely.
        return true;
      }
      if (ownerMeta.phase === "done" || ownerMeta.phase === "error") return true;
      // Owner reports running — but it may have crashed without updating
      // phase. If the run was started on this host and we recorded its
      // PID, check whether the process is still alive. A dead PID means
      // the run is genuinely gone and the lock can be reclaimed now,
      // without waiting out STALE_LOCK_MS. Cross-host (different
      // hostname) we can't probe, so we fall through to the timestamp
      // check.
      if (
        ownerMeta.pid !== undefined &&
        ownerMeta.hostname !== undefined &&
        ownerMeta.hostname === localHostname &&
        !isPidAlive(ownerMeta.pid)
      ) {
        return true;
      }
      // Records written before lockedAt existed have no timestamp; treat
      // those as old enough to reclaim so we can recover legacy locked
      // state.
      if (!r.lockedAt) return true;
      const ageMs = Date.now() - new Date(r.lockedAt).getTime();
      return ageMs >= STALE_LOCK_MS;
    };

    // Load file records and pick which to process
    const allRecords = loadAllFileRecords(projectId);
    let toProcess: FileRecord[];

    // Direct mode: caller passed an exact file list. Bypass the
    // scanner-state filter, the noise sort, and reinvestigate logic — the
    // user's list IS the work. Records are loaded by path; we expect
    // `scanFiles()` to have run first so every path has a record on disk.
    if (params.filePaths !== undefined) {
      const wanted = new Set(params.filePaths.map((p) => p.replaceAll("\\", "/")));
      const byPath = new Map(allRecords.map((r) => [r.filePath, r]));
      const missing: string[] = [];
      toProcess = [];
      for (const p of wanted) {
        const r = byPath.get(p);
        if (r) toProcess.push(r);
        else missing.push(p);
      }
      if (missing.length > 0) {
        console.warn(
          `[deepsec] process: ${missing.length} file(s) had no FileRecord and were skipped: ${missing.slice(0, 5).join(", ")}${missing.length > 5 ? "…" : ""}`,
        );
      }
    } else if (typeof reinvestigate === "number") {
      // Idempotent reinvestigate: `--reinvestigate <N>` is a *wave marker*.
      // The first run with a given N tags every productive analysis it
      // produces with `reinvestigateMarker = N`; re-running with the same N
      // (e.g. after some sandboxes failed) skips files that already carry
      // this marker for the same agent. Silent-failure entries don't count
      // since they had 0 output tokens — the agent never actually ran.
      //
      // To request a NEW pass, bump N (21 is "wave 21"). Different agents
      // get separate markers because we filter by agentType.
      toProcess = allRecords.filter((r) => {
        const alreadyDone = (r.analysisHistory ?? []).some((h) => {
          if ((h.usage?.outputTokens ?? 0) <= 0) return false;
          if (h.agentType !== agentType) return false;
          // A revalidate entry doesn't satisfy a process wave: revalidation
          // doesn't re-investigate, it just attaches verdicts. Even if a
          // revalidate entry somehow carried `reinvestigateMarker` (today
          // it doesn't), counting it here would silently skip files that
          // still need a fresh process pass.
          if (h.phase === "revalidate") return false;
          return h.reinvestigateMarker === reinvestigate;
        });
        return !alreadyDone;
      });
    } else if (reinvestigate) {
      toProcess = allRecords;
    } else {
      toProcess = allRecords.filter(
        (r) =>
          r.status === "pending" ||
          r.status === "error" ||
          // Reclaim a `processing` record from another run only when the
          // owning lock is genuinely abandoned. The previous version
          // reclaimed unconditionally, which let two concurrent runs
          // both pick up the same file and clobber each other on
          // write. See `isReclaimableLock` for the exact criteria.
          (r.status === "processing" && r.lockedByRunId !== runId && isReclaimableLock(r)),
      );
    }

    // Apply manifest filter (exact file list from sandbox orchestrator)
    if (manifestFilePaths) {
      toProcess = toProcess.filter((r) => manifestFilePaths!.has(r.filePath));
    }

    // Slug filters: --only-slugs and --skip-slugs
    const onlySet =
      params.onlySlugs && params.onlySlugs.length > 0 ? new Set(params.onlySlugs) : undefined;
    const skipSet =
      params.skipSlugs && params.skipSlugs.length > 0 ? new Set(params.skipSlugs) : undefined;
    if (onlySet || skipSet) {
      toProcess = toProcess.filter((r) => {
        const slugs = r.candidates.map((c) => c.vulnSlug);
        if (onlySet && !slugs.some((s) => onlySet.has(s))) return false;
        // Keep the record if any slug is NOT in the skip set — if all are skipped, drop it
        if (skipSet && slugs.length > 0 && slugs.every((s) => skipSet.has(s))) return false;
        return true;
      });
    }

    // Sort: noise tier first (precise > normal > noisy), then priority paths
    toProcess.sort((a, b) => {
      // Primary: noise tier (precise matchers first)
      const aSlugs = a.candidates.map((c) => c.vulnSlug);
      const bSlugs = b.candidates.map((c) => c.vulnSlug);
      const noiseDiff = noiseScore(aSlugs) - noiseScore(bSlugs);
      if (noiseDiff !== 0) return noiseDiff;

      // Secondary: priority paths from config
      if (projectConfig.priorityPaths && projectConfig.priorityPaths.length > 0) {
        const priorities = projectConfig.priorityPaths;
        const aPri = priorities.findIndex((p) => a.filePath.startsWith(p));
        const bPri = priorities.findIndex((p) => b.filePath.startsWith(p));
        const aScore = aPri === -1 ? priorities.length : aPri;
        const bScore = bPri === -1 ? priorities.length : bPri;
        if (aScore !== bScore) return aScore - bScore;
      }

      // Tertiary: more candidate matches = higher priority
      return b.candidates.length - a.candidates.length;
    });

    if (toProcess.length === 0) {
      emitProgress({
        type: "all_complete",
        message: "No files to process",
      });
      completeRun(projectId, runId, "done", { filesProcessed: 0 });
      return { runId, analysisCount: 0, findingCount: 0, errorBatchCount: 0 };
    }

    // Apply path filter
    if (params.filter) {
      toProcess = toProcess.filter((r) => r.filePath.startsWith(params.filter!));
    }

    // Apply limit
    if (params.limit && toProcess.length > params.limit) {
      toProcess = toProcess.slice(0, params.limit);
    }

    // Atomic claim under a per-project mutex. Without serializing this
    // section, two `process()` invocations against the same project both
    // see the same pending records, both write status="processing" with
    // their own runId, and the loser's lock + later writes get clobbered.
    // The lock is held only for the few seconds of disk I/O it takes to
    // re-read each record and write a fresh lock — the real work runs
    // outside it, so concurrent runs against disjoint file sets don't
    // block each other. See acquireProcessLock for the mkdir-based atomic
    // primitive and the 1h stale-lock cutoff.
    const lockedAt = new Date().toISOString();
    const claimed: FileRecord[] = [];
    const inForceMode = !!reinvestigate || params.filePaths !== undefined;
    const releaseProcessLock = await acquireProcessLock(projectId, runId);
    try {
      for (const record of toProcess) {
        let current: FileRecord;
        try {
          const fresh = readFileRecord(projectId, record.filePath);
          if (!fresh) continue;
          current = fresh;
        } catch {
          continue;
        }

        const isOurs = current.lockedByRunId === runId;
        const isFreelyClaimable =
          current.status === "pending" ||
          current.status === "error" ||
          (current.status === "processing" &&
            current.lockedByRunId !== runId &&
            isReclaimableLock(current));
        if (!isOurs && !isFreelyClaimable && !inForceMode) {
          continue;
        }

        current.status = "processing";
        current.lockedByRunId = runId;
        current.lockedAt = lockedAt;
        writeFileRecord(current);

        // Mutate the in-memory snapshot we'll process from so downstream code
        // sees the same lock state.
        record.status = current.status;
        record.lockedByRunId = current.lockedByRunId;
        record.lockedAt = current.lockedAt;
        claimed.push(record);
      }
    } finally {
      releaseProcessLock();
    }
    toProcess = claimed;
    if (toProcess.length === 0) {
      emitProgress({
        type: "all_complete",
        message: "Nothing to claim — another run owned every candidate file.",
      });
      completeRun(projectId, runId, "done", { filesProcessed: 0 });
      return { runId, analysisCount: 0, findingCount: 0, errorBatchCount: 0 };
    }

    const batches = batchCandidates(toProcess, params.batchSize);
    let totalAnalyses = 0;
    let totalFindings = 0;
    let totalCostUsd = 0;
    let totalInputTokens = 0;
    let totalOutputTokens = 0;
    let totalDurationMs = 0;
    let batchesCompleted = 0;
    let batchesFailed = 0;
    let batchesInFlight = 0;
    const concurrency = params.concurrency ?? defaultConcurrency();

    // Quota cancellation: when one batch throws QuotaExhaustedError, every
    // other in-flight batch is using the same exhausted credential and will
    // fail on its next API call. Aborting the controller cancels the SDK's
    // in-flight HTTP request so workers exit immediately instead of waiting
    // for a polling tick. The captured `quotaExhausted` is returned to the
    // caller so the CLI can render a tailored remediation message.
    const quotaAbort = new AbortController();
    if (params.signal?.aborted) quotaAbort.abort(params.signal.reason);
    params.signal?.addEventListener("abort", () => quotaAbort.abort(params.signal?.reason), {
      once: true,
    });
    let quotaExhausted: { source: QuotaSource; rawMessage: string } | undefined;
    let costLimitReached: { limitUsd: number; actualUsd: number } | undefined;

    async function processBatch(batch: FileRecord[], i: number) {
      batchesInFlight++;
      emitProgress({
        type: "batch_started",
        message: `Processing batch ${i + 1}/${batches.length} (${batch.length} files, ${batchesInFlight} in flight)`,
        batchIndex: i,
        totalBatches: batches.length,
      });

      try {
        // When using the modular assembled prompt, INFO.md is already
        // injected by `assemblePrompt()` (between `---` separators after
        // the threat highlights). Pass `""` to the agent layer to avoid a
        // second `## Project Context` block being appended on top of it.
        // Custom-template callers don't go through the assembler, so they
        // still need the agent layer to inject INFO.md for them.
        const projectInfoForAgent = customPromptTemplate === undefined ? "" : projectInfo;
        const gen = agent.investigate({
          batch,
          projectRoot: effectiveRootPath,
          promptTemplate: buildBatchPrompt(batch),
          projectInfo: projectInfoForAgent,
          config,
          signal: quotaAbort.signal,
          projectId,
        });

        let result = await gen.next();
        while (!result.done) {
          emitProgress({
            type: "agent_progress",
            message: (result.value as AgentProgress).message,
            batchIndex: i,
            totalBatches: batches.length,
            agentProgress: result.value as AgentProgress,
          });
          result = await gen.next();
        }

        const output = result.value as InvestigateOutput;
        const { results, meta: batchMeta } = output;

        // Accumulate run-level stats
        totalCostUsd += batchMeta.costUsd ?? 0;
        totalInputTokens += batchMeta.usage?.inputTokens ?? 0;
        totalOutputTokens += batchMeta.usage?.outputTokens ?? 0;
        totalDurationMs += batchMeta.durationMs;

        // Cost / tokens / duration / turns are batch-level — one agent call
        // covers all files in the batch. Stamping the batch total onto every
        // file's analysisHistory entry inflates `metrics` totals by ~batch
        // size. Divide evenly so summing per-file entries gives the correct
        // run total. We split by the count of records that will actually
        // get an entry (results that match a record in the batch) — silent
        // skips don't dilute the share.
        const validResultCount = results.reduce(
          (n, r) => n + (batch.some((b) => b.filePath === r.filePath) ? 1 : 0),
          0,
        );
        const splitN = Math.max(1, validResultCount);
        const perFileCost = batchMeta.costUsd != null ? batchMeta.costUsd / splitN : undefined;
        const perFileUsage = batchMeta.usage
          ? {
              inputTokens: batchMeta.usage.inputTokens / splitN,
              outputTokens: batchMeta.usage.outputTokens / splitN,
              cacheReadInputTokens: batchMeta.usage.cacheReadInputTokens / splitN,
              cacheCreationInputTokens: batchMeta.usage.cacheCreationInputTokens / splitN,
            }
          : undefined;
        const perFileDurationMs = batchMeta.durationMs / splitN;
        const perFileDurationApiMs =
          batchMeta.durationApiMs != null ? batchMeta.durationApiMs / splitN : undefined;
        const perFileNumTurns =
          batchMeta.numTurns != null ? batchMeta.numTurns / splitN : undefined;

        // Update file records with results + metadata.
        //
        // Re-investigation always *merges* — existing findings are preserved
        // and only the agent's net-new findings (signature not already on the
        // file) get appended. Signature: vulnSlug + normalized title
        // (lowercase, trimmed). This tolerates minor wording drift while still
        // suppressing duplicates from re-runs. The first analysis on a file
        // (no prior findings) lands as-is.
        for (const res of results) {
          const record = batch.find((r) => r.filePath === res.filePath);
          if (!record) continue;

          const sig = (slug: string | undefined, title: string | undefined) =>
            `${slug ?? ""}::${(title ?? "").trim().toLowerCase()}`;
          const existing = new Set((record.findings ?? []).map((f) => sig(f.vulnSlug, f.title)));
          const newFindings = res.findings
            .filter((f) => !existing.has(sig(f.vulnSlug, f.title)))
            // Stamp the originating run so PR comments and post-run
            // tooling can filter to net-new findings only. Findings from
            // earlier runs keep their (older) producedByRunId — or
            // undefined for findings written before this field existed.
            .map((f) => ({ ...f, producedByRunId: runId }));
          record.findings = [...(record.findings ?? []), ...newFindings];
          // Stamp stable findingIds on the appended findings at creation
          // time (existing findings already have theirs from load).
          ensureFindingIds(record);
          const findingsForHistoryCount = newFindings.length;

          record.analysisHistory.push({
            runId,
            investigatedAt: new Date().toISOString(),
            durationMs: perFileDurationMs,
            durationApiMs: perFileDurationApiMs,
            agentType,
            model,
            modelConfig: config,
            agentSessionId: batchMeta.agentSessionId,
            findingCount: findingsForHistoryCount,
            numTurns: perFileNumTurns,
            phase: "process",
            costUsd: perFileCost,
            usage: perFileUsage,
            refusal: batchMeta.refusal,
            codexStderr: batchMeta.codexStderr,
            reinvestigateMarker: typeof reinvestigate === "number" ? reinvestigate : undefined,
          });
          record.status = "analyzed";
          record.lockedByRunId = undefined;
          record.lockedAt = undefined;
          try {
            enrichFileRecord(record, effectiveRootPath);
          } catch (e) {
            console.error(
              `[deepsec] enrich failed for ${record.filePath}: ${e instanceof Error ? e.message : e}`,
            );
          }
          writeFileRecord(record);

          totalAnalyses++;
          // Count net-new only — re-runs of analyzed files that produce
          // duplicates of existing findings shouldn't inflate the run
          // total (and shouldn't fail the CLI exit gate in direct mode).
          totalFindings += newFindings.length;
        }

        // Mark any files not in results as error
        for (const record of batch) {
          if (!results.some((r) => r.filePath === record.filePath)) {
            record.status = "error";
            record.lockedByRunId = undefined;
            record.lockedAt = undefined;
            writeFileRecord(record);
          }
        }

        batchesInFlight--;
        batchesCompleted++;
        if (
          params.maxCostUsd !== undefined &&
          totalCostUsd >= params.maxCostUsd &&
          !costLimitReached
        ) {
          costLimitReached = { limitUsd: params.maxCostUsd, actualUsd: totalCostUsd };
          quotaAbort.abort(new Error(`Cost limit $${params.maxCostUsd.toFixed(2)} reached`));
        }
        emitProgress({
          type: "batch_complete",
          message: `Batch ${i + 1}/${batches.length} complete: ${results.length} analyses, ${results.reduce((s, r) => s + r.findings.length, 0)} findings (${batchesInFlight} in flight, ${batchesCompleted}/${batches.length} done)`,
          batchIndex: i,
          totalBatches: batches.length,
        });
      } catch (err) {
        batchesInFlight--;
        batchesCompleted++;
        batchesFailed++;
        // Capture quota exhaustion exactly once: the first batch to trip
        // wins, and subsequent batches that also throw QuotaExhaustedError
        // (because they were already in-flight against the same empty
        // credential) get their classifier silently dropped — no point
        // logging "quota exhausted" N times. The abort below cancels them.
        if (err instanceof QuotaExhaustedError && !quotaExhausted) {
          quotaExhausted = { source: err.source, rawMessage: err.rawMessage };
          quotaAbort.abort(err);
        }
        for (const record of batch) {
          record.status = "error";
          record.lockedByRunId = undefined;
          record.lockedAt = undefined;
          writeFileRecord(record);
        }
        emitProgress({
          type: "batch_complete",
          message: `Batch ${i + 1}/${batches.length} failed: ${err instanceof Error ? err.message : String(err)} (${batchesInFlight} in flight, ${batchesCompleted}/${batches.length} done)`,
          batchIndex: i,
          totalBatches: batches.length,
        });
      }
    }

    if (concurrency <= 1) {
      // Sequential
      for (let i = 0; i < batches.length; i++) {
        // Stop pulling new batches once any earlier batch has tripped quota
        // — the credential is empty for the whole run.
        if (quotaAbort.signal.aborted) break;
        await processBatch(batches[i], i);
      }
    } else {
      // Concurrent with limited parallelism
      let nextIdx = 0;
      async function worker() {
        while (nextIdx < batches.length) {
          if (quotaAbort.signal.aborted) return;
          const idx = nextIdx++;
          await processBatch(batches[idx], idx);
        }
      }
      const workers = Array.from({ length: Math.min(concurrency, batches.length) }, () => worker());
      await Promise.all(workers);
    }

    // Cost/quota stops can leave batches that were claimed up front but never
    // launched. Release those records immediately so the next resumable run
    // does not have to wait for stale-lock reclamation.
    if (costLimitReached || quotaExhausted) {
      for (const record of toProcess) {
        if (record.status !== "processing" || record.lockedByRunId !== runId) continue;
        record.status = "pending";
        record.lockedByRunId = undefined;
        record.lockedAt = undefined;
        writeFileRecord(record);
      }
    }

    completeRun(projectId, runId, "done", {
      filesProcessed: totalAnalyses,
      findingsCount: totalFindings,
      totalCostUsd,
      totalInputTokens,
      totalOutputTokens,
      totalDurationMs,
    });

    emitProgress({
      type: "all_complete",
      message: quotaExhausted
        ? `Processing stopped: ${quotaExhausted.source} quota/credits exhausted (${totalAnalyses} analyses, ${batchesFailed} batch(es) failed before stop)`
        : `Processing complete: ${totalAnalyses} analyses, ${totalFindings} findings${batchesFailed > 0 ? `, ${batchesFailed} batch(es) failed` : ""}`,
    });

    return {
      runId,
      analysisCount: totalAnalyses,
      findingCount: totalFindings,
      errorBatchCount: batchesFailed,
      quotaExhausted,
      totalCostUsd,
      costLimitReached,
    };
  } catch (err) {
    // Body threw before completing. Flip phase to "error" so the
    // run's locks become reclaimable on the next call rather than
    // staying "running" with a live PID (which the same-process
    // case would otherwise treat as a healthy owner).
    try {
      completeRun(projectId, runId, "error");
    } catch {
      // best-effort
    }
    throw err;
  } finally {
    unregisterRun();
  }
}

// --- Revalidation ---

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  HIGH_BUG: 3,
  BUG: 4,
  LOW: 5,
};

export async function revalidate(params: {
  projectId: string;
  runId?: string;
  agentType?: string;
  config?: Record<string, unknown>;
  minSeverity?: Severity;
  force?: boolean;
  limit?: number;
  concurrency?: number;
  batchSize?: number;
  filter?: string;
  /** Override rootPath from project.json (for sandbox execution) */
  rootPathOverride?: string;
  /** Path to JSON manifest file listing exact file paths to revalidate */
  manifestPath?: string;
  /** Only revalidate findings with one of these vulnSlugs */
  onlySlugs?: string[];
  /** Skip findings with any of these vulnSlugs */
  skipSlugs?: string[];
  /**
   * Allow a `duplicateOf` reference to resolve to a finding in another
   * file of the same batch. Default false — duplicates are same-file
   * only, matching the prompt's instructions.
   */
  crossFileDuplicates?: boolean;
  onProgress?: (progress: ProcessProgress) => void;
}): Promise<{
  runId: string;
  revalidated: number;
  truePositives: number;
  falsePositives: number;
  fixed: number;
  uncertain: number;
  duplicates: number;
  /**
   * DUPE verdicts the agent produced that we discarded because they
   * pointed at no primary, at a non-existent primary, at themselves, or
   * at another duplicate. They stay unrevalidated and will be retried
   * on the next run.
   */
  duplicatesRejected: number;
  /** Total findings this run asked the agent(s) to revalidate. */
  requested: number;
  /**
   * Findings that still have no persisted verdict after in-session
   * repair and adaptive batch splitting. Non-empty means the run is
   * incomplete — the CLI treats this as a failure exit. Each entry
   * identifies the finding so a follow-up run can target it.
   */
  unresolved: Array<{ findingId: string; filePath: string; title: string }>;
  /** Same semantics as `process()` — see that return type. */
  quotaExhausted?: { source: QuotaSource; rawMessage: string };
}> {
  const {
    projectId,
    agentType = "claude-agent-sdk",
    config = {},
    minSeverity,
    force = false,
    crossFileDuplicates = false,
  } = params;

  const emitProgress = (progress: ProcessProgress) => {
    try {
      params.onProgress?.(progress);
    } catch (err) {
      console.error(
        `[deepsec] progress callback error: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  };

  const project = readProjectConfig(projectId);
  const effectiveRootPath = params.rootPathOverride
    ? path.resolve(params.rootPathOverride)
    : project.rootPath;

  if (!fs.existsSync(effectiveRootPath)) {
    const source = params.rootPathOverride ? "--root" : `data/${projectId}/project.json:rootPath`;
    throw new Error(
      `Project root does not exist: ${effectiveRootPath}\n` +
        `  (came from ${source})\n` +
        `  Re-scan with the correct path: deepsec scan --project-id ${projectId} --root <correct-path>`,
    );
  }

  // Load manifest if provided
  let manifestFilePaths: Set<string> | undefined;
  if (params.manifestPath) {
    const raw = JSON.parse(fs.readFileSync(params.manifestPath, "utf-8"));
    if (!Array.isArray(raw)) throw new Error("Manifest must be a JSON array of file paths");
    manifestFilePaths = new Set(raw as string[]);
  }

  const infoPath = path.join(dataDir(projectId), "INFO.md");
  let projectInfo = "";
  try {
    projectInfo = fs.readFileSync(infoPath, "utf-8");
  } catch {}

  const model = (config.model as string) ?? "claude-opus-4-8";

  let runId: string;
  if (params.runId) {
    runId = params.runId;
  } else {
    const meta = createRunMeta({
      projectId,
      rootPath: effectiveRootPath,
      type: "revalidate",
      processorConfig: { agentType, model, modelConfig: config },
    });
    writeRunMeta(meta);
    runId = meta.runId;
  }

  // Same shutdown handling as process(): revalidate doesn't lock
  // FileRecords, but the RunMeta itself can otherwise be stranded at
  // phase="running" forever on Ctrl+C, which is misleading in status
  // listings.
  const unregisterRun = registerActiveRun(projectId, runId);

  try {
    const registry = createDefaultAgentRegistry();
    const maybeAgent = registry.get(agentType);
    if (!maybeAgent) {
      throw new Error(`Unknown agent type: ${agentType}`);
    }
    const agent = maybeAgent;

    // Load files that have findings needing revalidation
    const revalOnlySet =
      params.onlySlugs && params.onlySlugs.length > 0 ? new Set(params.onlySlugs) : undefined;
    const revalSkipSet =
      params.skipSlugs && params.skipSlugs.length > 0 ? new Set(params.skipSlugs) : undefined;
    const allRecords = loadAllFileRecords(projectId);
    let toRevalidate = allRecords.filter((r) => {
      if (r.findings.length === 0) return false;
      if (params.filter && !r.filePath.startsWith(params.filter)) return false;

      const unrevalidated = r.findings.filter((f) => {
        if (!force && f.revalidation) return false;
        if (minSeverity && SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[minSeverity]) return false;
        if (revalOnlySet && !revalOnlySet.has(f.vulnSlug)) return false;
        if (revalSkipSet?.has(f.vulnSlug)) return false;
        return true;
      });
      return unrevalidated.length > 0;
    });

    // Apply manifest filter (exact file list from sandbox orchestrator)
    if (manifestFilePaths) {
      toRevalidate = toRevalidate.filter((r) => manifestFilePaths!.has(r.filePath));
    }

    // Sort by severity (CRITICAL first) then noise tier
    toRevalidate.sort((a, b) => {
      const aBest = Math.min(...a.findings.map((f) => SEVERITY_ORDER[f.severity]));
      const bBest = Math.min(...b.findings.map((f) => SEVERITY_ORDER[f.severity]));
      if (aBest !== bBest) return aBest - bBest;
      return (
        noiseScore(a.candidates.map((c) => c.vulnSlug)) -
        noiseScore(b.candidates.map((c) => c.vulnSlug))
      );
    });

    if (params.limit && toRevalidate.length > params.limit) {
      toRevalidate = toRevalidate.slice(0, params.limit);
    }

    if (toRevalidate.length === 0) {
      emitProgress({
        type: "all_complete",
        message: "No findings to revalidate",
      });
      completeRun(projectId, runId, "done", { findingsRevalidated: 0 });
      return {
        runId,
        revalidated: 0,
        truePositives: 0,
        falsePositives: 0,
        fixed: 0,
        uncertain: 0,
        duplicates: 0,
        duplicatesRejected: 0,
        requested: 0,
        unresolved: [],
      };
    }

    let totalRevalidated = 0;
    let totalTP = 0;
    let totalFP = 0;
    let totalFixed = 0;
    let totalUncertain = 0;
    let totalDuplicate = 0;
    // Rejected DUPEs keyed by findingId — split retries re-reject the
    // same finding, and counting per attempt would inflate the stat.
    const dupeRejectedIds = new Set<string>();
    let totalCostUsd = 0;
    let totalRequested = 0;
    const totalUnresolved: ExpectedFinding[] = [];
    let batchesCompleted = 0;
    let batchesInFlight = 0;
    const concurrency = params.concurrency ?? defaultConcurrency();
    const batchSize = params.batchSize ?? 5;

    const batches = batchCandidates(toRevalidate, batchSize);

    // Same quota-cancellation pattern as process(); see that block for why.
    const quotaAbort = new AbortController();
    let quotaExhausted: { source: QuotaSource; rawMessage: string } | undefined;

    // Every agent invocation (initial batch, per-file retry, per-finding
    // retry) drops one artifact here: raw model responses, parsed
    // verdicts, reconciliation diagnostics, and repair prompts. Lives in
    // the project data dir — not an ephemeral debug location — so
    // failures can be diagnosed and rescored without repeating model
    // work.
    const artifactsDir = path.join(dataDir(projectId), "revalidation", runId);
    let artifactSeq = 0;
    const writeInvocationArtifact = (artifact: Record<string, unknown>): void => {
      try {
        fs.mkdirSync(artifactsDir, { recursive: true });
        const name = `invocation-${String(artifactSeq++).padStart(3, "0")}.json`;
        fs.writeFileSync(
          path.join(artifactsDir, name),
          JSON.stringify(artifact, null, 2) + "\n",
          "utf-8",
        );
      } catch (e) {
        console.error(
          `[deepsec] failed to write revalidation artifact: ${e instanceof Error ? e.message : e}`,
        );
      }
    };

    interface InvocationResult {
      expectedCount: number;
      returnedCount: number;
      matchedCount: number;
      persistedCount: number;
      /** Expected findings that still have no persisted verdict. */
      unresolved: ExpectedFinding[];
    }

    /**
     * One agent call + reconcile + persist. Verdicts that reconcile
     * unambiguously are applied and written to disk IMMEDIATELY — a miss
     * elsewhere in the batch never discards them. Returns the findings
     * that remain unresolved so the caller can retry just those.
     */
    async function runRevalidateInvocation(inv: {
      files: FileRecord[];
      onlyFindingIds?: string[];
      batchIdx: number;
      label: string;
    }): Promise<InvocationResult> {
      const { files, onlyFindingIds, batchIdx, label } = inv;
      const onlySet = onlyFindingIds ? new Set(onlyFindingIds) : undefined;
      const expected = expectedFindingsForBatch(files, { force, onlyFindingIds: onlySet });
      if (expected.length === 0) {
        return {
          expectedCount: 0,
          returnedCount: 0,
          matchedCount: 0,
          persistedCount: 0,
          unresolved: [],
        };
      }

      const gen = agent.revalidate({
        batch: files,
        projectRoot: effectiveRootPath,
        projectInfo,
        config,
        force,
        onlyFindingIds,
        signal: quotaAbort.signal,
        projectId,
      });

      let result = await gen.next();
      while (!result.done) {
        emitProgress({
          type: "agent_progress",
          message: (result.value as AgentProgress).message,
          batchIndex: batchIdx,
          totalBatches: batches.length,
          agentProgress: result.value as AgentProgress,
        });
        result = await gen.next();
      }

      const output = result.value as RevalidateOutput;
      const batchMeta = output.meta;
      totalCostUsd += batchMeta.costUsd ?? 0;

      const reconciled = reconcileVerdicts(expected, output.verdicts);
      // Translates "F2"-style duplicateOf references (the short aliases
      // the prompt displayed) back to stable findingIds.
      const aliasMap = buildAliasMap(expected);

      // Index findings by their stable id — reconciliation already
      // resolved every match to a findingId, so application is exact.
      const byId = new Map<
        string,
        { file: FileRecord; finding: (typeof files)[0]["findings"][0] }
      >();
      for (const file of files) {
        for (const finding of file.findings) {
          if (finding.findingId) byId.set(finding.findingId, { file, finding });
        }
      }

      // Two-pass apply + writeback. Pass 1 applies every non-duplicate
      // verdict. Pass 2 applies "duplicate" verdicts, but only when the
      // referenced primary has a non-duplicate verdict — either freshly
      // applied in pass 1 or already on the file from a prior run. This
      // enforces the invariant that every equivalence class of
      // duplicates has exactly one non-duplicate primary; an all-DUPE
      // group gets every member rejected (they stay unresolved and get
      // retried in the split stage / next run).
      const nowIso = new Date().toISOString();
      const resolvedIds = new Set<string>();
      let persistedCount = 0;
      const dupeMatches: typeof reconciled.matches = [];

      for (const m of reconciled.matches) {
        if (m.verdict.verdict === "duplicate") {
          dupeMatches.push(m);
          continue;
        }
        const target = byId.get(m.expected.findingId);
        if (!target) continue;
        const { finding } = target;
        // Never overwrite the manual accepted-risk marker, and never
        // re-apply over an existing verdict outside force mode (keeps
        // restarts/retries idempotent). Both count as resolved so the
        // finding isn't retried.
        if (finding.revalidation?.verdict === "accepted-risk") {
          resolvedIds.add(m.expected.findingId);
          continue;
        }
        if (finding.revalidation && !force) {
          resolvedIds.add(m.expected.findingId);
          continue;
        }
        finding.revalidation = {
          verdict: m.verdict.verdict,
          reasoning: m.verdict.reasoning,
          adjustedSeverity: m.verdict.adjustedSeverity,
          revalidatedAt: nowIso,
          runId,
          model,
        };
        if (m.verdict.adjustedSeverity) {
          finding.severity = m.verdict.adjustedSeverity;
        }
        resolvedIds.add(m.expected.findingId);
        dupeRejectedIds.delete(m.expected.findingId);
        persistedCount++;
        totalRevalidated++;
        if (m.verdict.verdict === "true-positive") totalTP++;
        else if (m.verdict.verdict === "false-positive") totalFP++;
        else if (m.verdict.verdict === "fixed") totalFixed++;
        else totalUncertain++;
      }

      for (const m of dupeMatches) {
        const target = byId.get(m.expected.findingId);
        if (!target) continue;
        const { file, finding } = target;
        if (finding.revalidation?.verdict === "accepted-risk") {
          resolvedIds.add(m.expected.findingId);
          continue;
        }
        if (finding.revalidation && !force) {
          resolvedIds.add(m.expected.findingId);
          continue;
        }
        // `duplicateOf` resolves through the same reconciliation-style
        // matching: short alias / findingId first, then exact /
        // normalized title. Reject self-reference, unresolvable
        // reference, and pointing at another DUPE. Rejected DUPEs are
        // NOT discarded silently — they stay unresolved and are retried
        // by the split stage.
        const ref = m.verdict.duplicateOf;
        if (!ref) {
          dupeRejectedIds.add(m.expected.findingId);
          continue;
        }
        const primary = resolveDuplicateRef({
          ref,
          file,
          batch: files,
          crossFile: crossFileDuplicates,
          aliasMap,
        });
        if (!primary || primary.finding === finding) {
          dupeRejectedIds.add(m.expected.findingId);
          continue;
        }
        if (!primary.finding.revalidation || primary.finding.revalidation.verdict === "duplicate") {
          dupeRejectedIds.add(m.expected.findingId);
          continue;
        }
        finding.revalidation = {
          verdict: "duplicate",
          reasoning: m.verdict.reasoning,
          // Persist the primary's stable id (falls back to the raw ref
          // for pre-findingId primaries, matching the legacy format).
          duplicateOf: primary.finding.findingId ?? ref,
          revalidatedAt: nowIso,
          runId,
          model,
        };
        resolvedIds.add(m.expected.findingId);
        dupeRejectedIds.delete(m.expected.findingId);
        persistedCount++;
        totalRevalidated++;
        totalDuplicate++;
      }

      // Push a per-file `analysisHistory` entry for this invocation.
      // Without this, revalidate cost is only ever recorded in
      // `runMeta.stats.totalCostUsd` and is invisible to the `metrics`
      // command (which aggregates strictly off `record.analysisHistory`).
      // We split invocation-level cost / tokens / duration / turns evenly
      // over the files so per-file totals add up to actual spend.
      const splitN = Math.max(1, files.length);
      const perFileCost = batchMeta.costUsd != null ? batchMeta.costUsd / splitN : undefined;
      const perFileUsage = batchMeta.usage
        ? {
            inputTokens: batchMeta.usage.inputTokens / splitN,
            outputTokens: batchMeta.usage.outputTokens / splitN,
            cacheReadInputTokens: batchMeta.usage.cacheReadInputTokens / splitN,
            cacheCreationInputTokens: batchMeta.usage.cacheCreationInputTokens / splitN,
          }
        : undefined;
      const perFileDurationMs = batchMeta.durationMs / splitN;
      const perFileDurationApiMs =
        batchMeta.durationApiMs != null ? batchMeta.durationApiMs / splitN : undefined;
      const perFileNumTurns = batchMeta.numTurns != null ? batchMeta.numTurns / splitN : undefined;
      const investigatedAt = new Date().toISOString();

      for (const file of files) {
        const persistedForFile = reconciled.matches.filter(
          (m) => resolvedIds.has(m.expected.findingId) && m.expected.filePath === file.filePath,
        ).length;
        file.analysisHistory.push({
          runId,
          investigatedAt,
          durationMs: perFileDurationMs,
          durationApiMs: perFileDurationApiMs,
          agentType,
          model,
          modelConfig: config,
          agentSessionId: batchMeta.agentSessionId,
          findingCount: persistedForFile,
          numTurns: perFileNumTurns,
          phase: "revalidate",
          costUsd: perFileCost,
          usage: perFileUsage,
          refusal: batchMeta.refusal,
          codexStderr: batchMeta.codexStderr,
        });

        try {
          enrichFileRecord(file, effectiveRootPath);
        } catch (e) {
          console.error(
            `[deepsec] enrich failed for ${file.filePath}: ${e instanceof Error ? e.message : e}`,
          );
        }
        writeFileRecord(file);
      }

      const unresolved = expected.filter((e) => !resolvedIds.has(e.findingId));

      writeInvocationArtifact({
        batchIndex: batchIdx,
        label,
        timestamp: investigatedAt,
        files: files.map((f) => f.filePath),
        requested: expected,
        rawResponses: output.rawResponses,
        repairAttempts: output.repairAttempts,
        parsedVerdicts: output.verdicts,
        reconciliation: {
          matches: reconciled.matches.map((m) => m.diagnostic),
          missingFindingIds: reconciled.missing.map((e) => e.findingId),
          unknownVerdicts: reconciled.unknown,
          ambiguousVerdicts: reconciled.ambiguous,
        },
        persistedCount,
        unresolvedFindingIds: unresolved.map((e) => e.findingId),
      });

      return {
        expectedCount: expected.length,
        returnedCount: output.verdicts.length,
        matchedCount: reconciled.matches.length,
        persistedCount,
        unresolved,
      };
    }

    /**
     * Retry wrapper for the split stages: a non-quota failure in a
     * sub-invocation shouldn't sink verdicts already persisted for the
     * rest of the batch — record its findings as unresolved and move on.
     */
    async function runInvocationSafe(inv: {
      files: FileRecord[];
      onlyFindingIds: string[];
      batchIdx: number;
      label: string;
      fallbackUnresolved: ExpectedFinding[];
    }): Promise<InvocationResult> {
      try {
        return await runRevalidateInvocation(inv);
      } catch (err) {
        if (err instanceof QuotaExhaustedError) throw err;
        emitProgress({
          type: "agent_progress",
          message: `Retry ${inv.label} failed: ${err instanceof Error ? err.message : String(err)}`,
          batchIndex: inv.batchIdx,
          totalBatches: batches.length,
          agentProgress: {
            type: "error",
            message: `Retry ${inv.label} failed: ${err instanceof Error ? err.message : String(err)}`,
          },
        });
        return {
          expectedCount: inv.fallbackUnresolved.length,
          returnedCount: 0,
          matchedCount: 0,
          persistedCount: 0,
          unresolved: inv.fallbackUnresolved,
        };
      }
    }

    async function revalidateBatch(batch: FileRecord[], idx: number) {
      batchesInFlight++;
      const requested = expectedFindingsForBatch(batch, { force });
      totalRequested += requested.length;
      emitProgress({
        type: "batch_started",
        message: `Revalidating batch ${idx + 1}/${batches.length} (${batch.length} files, ${requested.length} findings, ${batchesInFlight} in flight)`,
        batchIndex: idx,
        totalBatches: batches.length,
      });

      try {
        const first = await runRevalidateInvocation({
          files: batch,
          batchIdx: idx,
          label: "initial",
        });
        let persisted = first.persistedCount;
        let unresolved = first.unresolved;

        // Adaptive split, stage 1: retry each file that still has
        // unresolved findings on its own — fewer identifiers to
        // reproduce, less output to format. Already-persisted findings
        // are never re-requested (onlyFindingIds pins the subset).
        const perFileRequestSize = new Map<string, number>();
        if (unresolved.length > 0 && !quotaAbort.signal.aborted) {
          emitProgress({
            type: "batch_complete",
            message: `Batch ${idx + 1}/${batches.length}: ${unresolved.length} unresolved after repair — retrying per file`,
            batchIndex: idx,
            totalBatches: batches.length,
          });
          const byFile = new Map<string, ExpectedFinding[]>();
          for (const e of unresolved) {
            byFile.set(e.filePath, [...(byFile.get(e.filePath) ?? []), e]);
          }
          const next: ExpectedFinding[] = [];
          for (const [filePath, findings] of byFile) {
            if (quotaAbort.signal.aborted) {
              next.push(...findings);
              continue;
            }
            const file = batch.find((f) => f.filePath === filePath);
            if (!file) {
              next.push(...findings);
              continue;
            }
            perFileRequestSize.set(filePath, findings.length);
            const res = await runInvocationSafe({
              files: [file],
              onlyFindingIds: findings.map((e) => e.findingId),
              batchIdx: idx,
              label: `retry-file:${filePath}`,
              fallbackUnresolved: findings,
            });
            persisted += res.persistedCount;
            next.push(...res.unresolved);
          }
          unresolved = next;
        }

        // Stage 2: findings from files that were retried with more than
        // one finding and still have misses get retried individually. A
        // finding whose per-file retry already asked for exactly one is
        // skipped — an individual retry would be the identical request.
        if (unresolved.length > 0 && !quotaAbort.signal.aborted) {
          const individual = unresolved.filter(
            (e) => (perFileRequestSize.get(e.filePath) ?? 0) > 1,
          );
          const skipped = unresolved.filter((e) => (perFileRequestSize.get(e.filePath) ?? 0) <= 1);
          const next: ExpectedFinding[] = [...skipped];
          for (const e of individual) {
            if (quotaAbort.signal.aborted) {
              next.push(e);
              continue;
            }
            const file = batch.find((f) => f.filePath === e.filePath);
            if (!file) {
              next.push(e);
              continue;
            }
            const res = await runInvocationSafe({
              files: [file],
              onlyFindingIds: [e.findingId],
              batchIdx: idx,
              label: `retry-finding:${e.findingId}`,
              fallbackUnresolved: [e],
            });
            persisted += res.persistedCount;
            next.push(...res.unresolved);
          }
          unresolved = next;
        }

        totalUnresolved.push(...unresolved);

        batchesInFlight--;
        batchesCompleted++;
        emitProgress({
          type: "batch_complete",
          message: `Batch ${idx + 1}/${batches.length}: requested ${first.expectedCount}, returned ${first.returnedCount}, matched ${first.matchedCount}, persisted ${persisted}${
            unresolved.length > 0 ? `, unresolved ${unresolved.length}` : ""
          } (${batchesInFlight} in flight, ${batchesCompleted}/${batches.length} done)`,
          batchIndex: idx,
          totalBatches: batches.length,
        });
      } catch (err) {
        batchesInFlight--;
        batchesCompleted++;
        if (err instanceof QuotaExhaustedError && !quotaExhausted) {
          quotaExhausted = { source: err.source, rawMessage: err.rawMessage };
          quotaAbort.abort(err);
        }
        // Whatever this batch persisted before the throw is already on
        // disk; only the requested findings that never got a verdict are
        // lost, and they surface as unresolved. (In force mode a finding
        // counts as done only when THIS run wrote its verdict.)
        for (const e of requested) {
          const file = batch.find((f) => f.filePath === e.filePath);
          const finding = file?.findings.find((f) => f.findingId === e.findingId);
          if (!finding) continue;
          const doneThisRun =
            finding.revalidation !== undefined &&
            (!force ||
              finding.revalidation.runId === runId ||
              finding.revalidation.verdict === "accepted-risk");
          if (!doneThisRun) totalUnresolved.push(e);
        }
        emitProgress({
          type: "batch_complete",
          message: `Batch ${idx + 1}/${batches.length} failed: ${err instanceof Error ? err.message : String(err)} (${batchesInFlight} in flight, ${batchesCompleted}/${batches.length} done)`,
          batchIndex: idx,
          totalBatches: batches.length,
        });
      }
    }

    if (concurrency <= 1) {
      for (let i = 0; i < batches.length; i++) {
        if (quotaAbort.signal.aborted) break;
        await revalidateBatch(batches[i], i);
      }
    } else {
      let nextIdx = 0;
      async function worker() {
        while (nextIdx < batches.length) {
          if (quotaAbort.signal.aborted) return;
          const idx = nextIdx++;
          await revalidateBatch(batches[idx], idx);
        }
      }
      await Promise.all(
        Array.from({ length: Math.min(concurrency, batches.length) }, () => worker()),
      );
    }

    completeRun(projectId, runId, "done", {
      findingsRevalidated: totalRevalidated,
      truePositives: totalTP,
      falsePositives: totalFP,
      fixed: totalFixed,
      uncertain: totalUncertain,
      duplicates: totalDuplicate,
      totalCostUsd,
    });

    const totalDupeRejected = dupeRejectedIds.size;
    const dupeRejectedSuffix = totalDupeRejected > 0 ? `, ${totalDupeRejected} DUPE rejected` : "";
    const unresolvedSuffix =
      totalUnresolved.length > 0 ? `, ${totalUnresolved.length} UNRESOLVED` : "";
    emitProgress({
      type: "all_complete",
      message: quotaExhausted
        ? `Revalidation stopped: ${quotaExhausted.source} quota/credits exhausted (${totalRevalidated} verdicts before stop)`
        : `Revalidation complete: ${totalRevalidated}/${totalRequested} findings — TP: ${totalTP}, FP: ${totalFP}, Fixed: ${totalFixed}, Uncertain: ${totalUncertain}, Dupe: ${totalDuplicate}${dupeRejectedSuffix}${unresolvedSuffix}`,
    });

    return {
      runId,
      revalidated: totalRevalidated,
      truePositives: totalTP,
      falsePositives: totalFP,
      fixed: totalFixed,
      uncertain: totalUncertain,
      duplicates: totalDuplicate,
      duplicatesRejected: totalDupeRejected,
      requested: totalRequested,
      unresolved: totalUnresolved,
      quotaExhausted,
    };
  } catch (err) {
    try {
      completeRun(projectId, runId, "error");
    } catch {
      // best-effort
    }
    throw err;
  } finally {
    unregisterRun();
  }
}

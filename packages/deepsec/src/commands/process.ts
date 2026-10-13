import fs from "node:fs";
import path from "node:path";
import { ensureProject, readProjectConfig } from "@deepsec/core";
import { process as processRun } from "@deepsec/processor";
import { scanFiles } from "@deepsec/scanner";
import { buildAgentConfig } from "../agent-config.js";
import { defaultModelForAgent } from "../agent-defaults.js";
import { resolveFiles } from "../file-sources.js";
import { BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW } from "../formatters.js";
import { renderPrComment } from "../pr-comment.js";
import { applyConfiguredModelRoute, assertAgentCredential } from "../preflight.js";
import { renderQuotaMessage } from "../quota-message.js";
import { resolveAgentType } from "../resolve-agent-type.js";
import { resolveProjectId, resolveProjectIdForDirect } from "../resolve-project-id.js";

function logProgress(progress: {
  type: string;
  message: string;
  batchIndex?: number;
  totalBatches?: number;
  agentProgress?: { type: string; message: string };
}) {
  try {
    switch (progress.type) {
      case "batch_started":
        console.log(
          `${BOLD}Batch ${(progress.batchIndex ?? 0) + 1}/${progress.totalBatches}${RESET}: ${progress.message}`,
        );
        break;
      case "agent_progress": {
        const ap = progress.agentProgress;
        if (!ap) break;
        switch (ap.type) {
          case "started":
            console.log(`  ${GREEN}>${RESET} ${ap.message}`);
            break;
          case "thinking":
            console.log(`  ${DIM}  ${ap.message}${RESET}`);
            break;
          case "tool_use":
            console.log(`  ${CYAN}  tool:${RESET} ${ap.message}`);
            break;
          case "complete":
            console.log(`  ${GREEN}  ${ap.message}${RESET}`);
            break;
          case "error":
            console.log(`  ${RED}  ${ap.message}${RESET}`);
            break;
          default:
            console.log(`  ${DIM}  ${ap.message}${RESET}`);
        }
        break;
      }
      case "batch_complete":
        console.log(`  ${progress.message}`);
        console.log();
        break;
      case "all_complete":
        console.log(`  ${DIM}${progress.message}${RESET}`);
        break;
    }
  } catch (err) {
    console.error(
      `  ${DIM}[progress render error: ${err instanceof Error ? err.message : String(err)}]${RESET}`,
    );
  }
}

function parseCsv(v: string | undefined): string[] | undefined {
  if (!v) return undefined;
  const parts = v
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  return parts.length > 0 ? parts : undefined;
}

export async function processCommand(opts: {
  projectId?: string;
  runId?: string;
  agent?: string;
  model?: string;
  maxTurns?: number;
  thinkingLevel?: string;
  aiProvider?: string;
  aiBaseUrl?: string;
  aiApiKeyEnv?: string;
  aiHeader?: string[];
  /** Commander yields `true` when bare; string (unparsed) when an arg is provided */
  reinvestigate?: boolean | string;
  limit?: number;
  concurrency?: number;
  filter?: string;
  batchSize?: number;
  root?: string;
  manifest?: string;
  onlySlugs?: string;
  skipSlugs?: string;
  // Direct invocation flags
  diff?: string;
  diffStaged?: boolean;
  diffWorking?: boolean;
  files?: string;
  filesFrom?: string;
  /** Commander auto-injects this from `--no-ignore` (default true). */
  ignore?: boolean;
  commentOut?: string;
}) {
  const isDirectMode =
    opts.diff !== undefined ||
    !!opts.diffStaged ||
    !!opts.diffWorking ||
    !!opts.files ||
    !!opts.filesFrom;

  if (isDirectMode) {
    return processDirectMode(opts);
  }
  return processStandardMode(opts);
}

async function processStandardMode(opts: Parameters<typeof processCommand>[0]) {
  const projectId = resolveProjectId(opts.projectId);
  const onlySlugs = parseCsv(opts.onlySlugs);
  const skipSlugs = parseCsv(opts.skipSlugs);
  const project = readProjectConfig(projectId);
  const effectiveRoot = opts.root ?? project.rootPath;
  const agentType = resolveAgentType(opts.agent);
  const model = opts.model ?? defaultModelForAgent(agentType);
  const resolvedRoute =
    !opts.aiApiKeyEnv && !opts.aiBaseUrl ? await applyConfiguredModelRoute(agentType) : undefined;
  const agentConfig = buildAgentConfig({ ...opts, model, modelRoute: resolvedRoute?.route });
  assertAgentCredential(agentType, { aiApiKeyEnv: opts.aiApiKeyEnv });

  // --reinvestigate  → true (re-investigate all)
  // --reinvestigate 2 → number (only files with < 2 analyses)
  let reinvestigate: boolean | number | undefined;
  if (opts.reinvestigate === true) {
    reinvestigate = true;
  } else if (typeof opts.reinvestigate === "string") {
    const n = parseInt(opts.reinvestigate, 10);
    if (Number.isNaN(n) || n < 1) {
      throw new Error(
        `--reinvestigate value must be a positive integer, got "${opts.reinvestigate}"`,
      );
    }
    reinvestigate = n;
  }

  console.log(`${BOLD}Processing${RESET} project ${BOLD}${projectId}${RESET}`);
  console.log(`  Agent: ${agentType} (${model})`);
  console.log(`  Root: ${effectiveRoot}${opts.root ? " (override)" : ""}`);
  if (opts.manifest) {
    console.log(`  Manifest: ${opts.manifest}`);
  }
  if (opts.runId) {
    console.log(`  Resuming run: ${opts.runId}`);
  }
  if (opts.concurrency && opts.concurrency > 1) {
    console.log(`  Concurrency: ${opts.concurrency} batches in parallel`);
  }
  if (reinvestigate === true) {
    console.log(`  ${YELLOW}Re-investigating all files (--reinvestigate)${RESET}`);
  } else if (typeof reinvestigate === "number") {
    console.log(`  ${YELLOW}Re-investigating files with < ${reinvestigate} analyses${RESET}`);
  }
  if (onlySlugs) console.log(`  Only slugs: ${onlySlugs.join(", ")}`);
  if (skipSlugs) console.log(`  Skip slugs: ${skipSlugs.join(", ")}`);
  console.log();

  const result = await processRun({
    projectId,
    runId: opts.runId,
    agentType,
    config: agentConfig,
    reinvestigate,
    limit: opts.limit,
    concurrency: opts.concurrency,
    filter: opts.filter,
    batchSize: opts.batchSize,
    rootPathOverride: opts.root,
    manifestPath: opts.manifest,
    onlySlugs,
    skipSlugs,
    onProgress: logProgress,
  });

  console.log(`${GREEN}Processing complete.${RESET} Run: ${BOLD}${result.runId}${RESET}`);
  console.log(`  Analyses: ${result.analysisCount}`);
  console.log(`  Findings: ${result.findingCount}`);
  if (result.errorBatchCount > 0) {
    console.log(`  ${RED}Errored batches: ${result.errorBatchCount}${RESET}`);
  }
  console.log();

  // Quota exhaustion is a fatal, run-stopping condition. Render the
  // tailored remediation message before the generic "errored batches"
  // banner so the user sees actionable guidance first, then exit non-zero
  // — same fail-loud contract as a regular agent failure.
  if (result.quotaExhausted) {
    console.log(
      renderQuotaMessage({
        source: result.quotaExhausted.source,
        rawMessage: result.quotaExhausted.rawMessage,
        command: "process",
        projectId,
      }),
    );
    process.exit(1);
  }

  // Standard-mode parity with direct-mode: a run that crashed agent
  // batches isn't a clean review. Print the runtime hint first so
  // operators see it on success runs, then fail-loud when applicable.
  if (result.errorBatchCount === 0) {
    console.log(`Next:`);
    console.log(`${DIM}pnpm deepsec report --project-id ${projectId}${RESET}`);
    return;
  }

  console.log(
    `${RED}${result.errorBatchCount} batch(es) errored — exiting 1 (agent failure, not a clean review).${RESET}`,
  );
  console.log(
    `${DIM}Files in those batches were marked status=error and will be retried on the next run.${RESET}`,
  );
  process.exit(1);
}

/**
 * Direct invocation: scan + process a specific file list.
 *
 * Lifecycle:
 *   1. Resolve the file list (git diff / explicit files / stdin).
 *   2. Auto-create the project on disk if it isn't in deepsec.config.ts.
 *   3. Run a scoped `scanFiles()` so each path has a FileRecord — this
 *      gives the agent regex-derived signals to anchor on, even when the
 *      diff includes files outside any matcher's pattern set.
 *   4. Run `process()` over those exact paths.
 *   5. Optionally render a PR-comment markdown.
 *   6. Exit 1 if any new finding was produced. CI gates on this.
 */
async function processDirectMode(opts: Parameters<typeof processCommand>[0]) {
  const sources = [
    opts.diff !== undefined ? "--diff" : null,
    opts.diffStaged ? "--diff-staged" : null,
    opts.diffWorking ? "--diff-working" : null,
    opts.files ? "--files" : null,
    opts.filesFrom ? "--files-from" : null,
  ].filter(Boolean) as string[];
  if (sources.length > 1) {
    throw new Error(`Conflicting file sources: ${sources.join(", ")}. Pick exactly one.`);
  }

  // Warn-and-ignore options that don't apply in direct mode. The user's
  // file list IS the filter — these flags would silently subset it
  // further, which is rarely what someone passing a diff wants.
  if (opts.reinvestigate !== undefined) {
    console.warn(
      `${YELLOW}Note: --reinvestigate is ignored in direct mode (file list is authoritative).${RESET}`,
    );
  }
  if (opts.manifest) {
    console.warn(
      `${YELLOW}Note: --manifest is ignored in direct mode; --files / --files-from / --diff* take precedence.${RESET}`,
    );
  }

  const { projectId, rootPath, autoCreated } = resolveProjectIdForDirect(opts.projectId, opts.root);

  // Materialize project on disk before resolveFiles needs it (no — resolveFiles
  // doesn't need it, but scanFiles + process do, and ensureProject also normalizes
  // the rootPath in data/<id>/project.json).
  ensureProject(projectId, rootPath);

  const agentType = resolveAgentType(opts.agent);
  const model = opts.model ?? defaultModelForAgent(agentType);
  const resolvedRoute =
    !opts.aiApiKeyEnv && !opts.aiBaseUrl ? await applyConfiguredModelRoute(agentType) : undefined;
  const agentConfig = buildAgentConfig({ ...opts, model, modelRoute: resolvedRoute?.route });
  assertAgentCredential(agentType, { aiApiKeyEnv: opts.aiApiKeyEnv });

  // Resolve the file list.
  const resolved = resolveFiles({
    rootPath,
    diff: opts.diff,
    diffStaged: opts.diffStaged,
    diffWorking: opts.diffWorking,
    files: parseCsv(opts.files),
    filesFrom: opts.filesFrom,
    // Commander's `--no-ignore` toggles `opts.ignore` to false; default true.
    noIgnore: opts.ignore === false,
  });

  console.log(`${BOLD}Direct process${RESET} project ${BOLD}${projectId}${RESET}`);
  if (autoCreated) {
    console.log(`  ${DIM}Auto-created project at ${rootPath}${RESET}`);
  }
  console.log(`  Source: ${resolved.sourceLabel}`);
  console.log(`  Files: ${resolved.filePaths.length}`);
  console.log(`  Agent: ${agentType} (${model})`);
  console.log(`  Root: ${rootPath}`);
  console.log();

  if (resolved.filePaths.length === 0) {
    console.log(`${YELLOW}No files matched ${resolved.sourceLabel} (after ignore filter).${RESET}`);
    console.log(`${GREEN}Nothing to process — exit 0.${RESET}`);
    return;
  }

  // Scan the listed files first to gather signals. Records get written
  // for every file, even those with no matcher hits.
  console.log(`${BOLD}Scanning ${resolved.filePaths.length} file(s)…${RESET}`);
  const scanResult = await scanFiles({
    projectId,
    root: rootPath,
    filePaths: resolved.filePaths,
    source: resolved.sourceLabel,
  });
  console.log(
    `  ${DIM}${scanResult.candidateCount} candidate(s) across ${scanResult.filesScanned} file(s)${RESET}`,
  );
  console.log();

  // Now investigate. process() loads the records scanFiles wrote.
  const result = await processRun({
    projectId,
    runId: opts.runId,
    agentType,
    config: agentConfig,
    concurrency: opts.concurrency,
    batchSize: opts.batchSize,
    rootPathOverride: rootPath,
    filePaths: resolved.filePaths,
    source: resolved.sourceLabel,
    onProgress: logProgress,
  });

  console.log(`${GREEN}Processing complete.${RESET} Run: ${BOLD}${result.runId}${RESET}`);
  console.log(`  Analyses: ${result.analysisCount}`);
  console.log(`  Findings: ${result.findingCount}`);
  if (result.errorBatchCount > 0) {
    console.log(`  ${RED}Errored batches: ${result.errorBatchCount}${RESET}`);
  }

  if (result.quotaExhausted) {
    console.log(
      renderQuotaMessage({
        source: result.quotaExhausted.source,
        rawMessage: result.quotaExhausted.rawMessage,
        command: "process",
        projectId,
      }),
    );
    process.exit(1);
  }

  // Hard-fail when any batch threw — that means the agent itself
  // failed to run (missing binary, auth error, etc.) on at least one
  // batch. A "clean run with 0 findings" is a green CI signal; we
  // can't let a silent agent crash mascarade as that.
  if (result.errorBatchCount > 0) {
    console.log();
    console.log(
      `${RED}${result.errorBatchCount} batch(es) errored — exiting 1 (agent failure, not a clean review).${RESET}`,
    );
    process.exit(1);
  }

  // Optionally write a PR-comment-shaped markdown for the workflow to
  // pass to github-script.
  if (opts.commentOut && result.findingCount > 0) {
    const md = renderPrComment({
      projectId,
      runId: result.runId,
      source: resolved.sourceLabel,
    });
    if (md) {
      const outPath = path.resolve(opts.commentOut);
      fs.mkdirSync(path.dirname(outPath), { recursive: true });
      fs.writeFileSync(outPath, md);
      console.log(`  ${DIM}Wrote PR comment to ${outPath}${RESET}`);
    }
  }

  if (result.findingCount > 0) {
    console.log();
    console.log(`${RED}${result.findingCount} new finding(s) — exiting 1${RESET}`);
    process.exit(1);
  }
  console.log();
  console.log(`${GREEN}No findings.${RESET}`);
}

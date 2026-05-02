import { readProjectConfig } from "@deepsec/core";
import { process as processRun } from "@deepsec/processor";
import { defaultModelForAgent } from "../agent-defaults.js";
import { BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW } from "../formatters.js";
import { assertAgentCredential } from "../preflight.js";
import { resolveProjectId } from "../resolve-project-id.js";

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
}) {
  const projectId = resolveProjectId(opts.projectId);
  const onlySlugs = parseCsv(opts.onlySlugs);
  const skipSlugs = parseCsv(opts.skipSlugs);
  const project = readProjectConfig(projectId);
  const effectiveRoot = opts.root ?? project.rootPath;
  const agentType = opts.agent ?? "claude-agent-sdk";
  const model = opts.model ?? defaultModelForAgent(agentType);

  assertAgentCredential(agentType);

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
    config: { model, ...(opts.maxTurns ? { maxTurns: opts.maxTurns } : {}) },
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
  console.log();
  console.log(`Next: ${DIM}pnpm deepsec report --project-id ${projectId}${RESET}`);
}

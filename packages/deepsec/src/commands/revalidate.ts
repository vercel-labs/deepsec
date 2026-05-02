import type { Severity } from "@deepsec/core";
import { readProjectConfig } from "@deepsec/core";
import { revalidate } from "@deepsec/processor";
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
          `${BOLD}[${(progress.batchIndex ?? 0) + 1}/${progress.totalBatches}]${RESET} ${progress.message}`,
        );
        break;
      case "agent_progress": {
        const ap = progress.agentProgress;
        if (!ap) break;
        if (ap.type === "tool_use") {
          console.log(`  ${CYAN}tool:${RESET} ${ap.message}`);
        } else if (ap.type === "complete") {
          console.log(`  ${GREEN}${ap.message}${RESET}`);
        } else if (ap.type === "error") {
          console.log(`  ${RED}${ap.message}${RESET}`);
        }
        break;
      }
      case "batch_complete":
        console.log(`  ${DIM}${progress.message}${RESET}`);
        break;
      case "all_complete":
        console.log(`${DIM}${progress.message}${RESET}`);
        break;
    }
  } catch {}
}

function parseCsv(v: string | undefined): string[] | undefined {
  if (!v) return undefined;
  const parts = v
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  return parts.length > 0 ? parts : undefined;
}

export async function revalidateCommand(opts: {
  projectId?: string;
  runId?: string;
  agent?: string;
  model?: string;
  maxTurns?: number;
  minSeverity?: string;
  force?: boolean;
  limit?: number;
  concurrency?: number;
  batchSize?: number;
  filter?: string;
  root?: string;
  manifest?: string;
  onlySlugs?: string;
  skipSlugs?: string;
}) {
  const projectId = resolveProjectId(opts.projectId);
  const _project = readProjectConfig(projectId);
  const agentType = opts.agent ?? "claude-agent-sdk";
  const model = opts.model ?? defaultModelForAgent(agentType);
  const minSeverity = opts.minSeverity as Severity | undefined;
  const onlySlugs = parseCsv(opts.onlySlugs);
  const skipSlugs = parseCsv(opts.skipSlugs);

  assertAgentCredential(agentType);

  console.log(`${BOLD}Revalidating${RESET} findings for project ${BOLD}${projectId}${RESET}`);
  console.log(`  Agent: ${agentType} (${model})`);
  if (minSeverity) console.log(`  Min severity: ${minSeverity}`);
  if (opts.force) console.log(`  ${YELLOW}Force re-checking all findings${RESET}`);
  if (opts.filter) console.log(`  Filter: ${opts.filter}`);
  if (onlySlugs) console.log(`  Only slugs: ${onlySlugs.join(", ")}`);
  if (skipSlugs) console.log(`  Skip slugs: ${skipSlugs.join(", ")}`);
  console.log();

  const result = await revalidate({
    projectId,
    runId: opts.runId,
    agentType,
    config: { model, ...(opts.maxTurns ? { maxTurns: opts.maxTurns } : {}) },
    minSeverity,
    force: opts.force,
    limit: opts.limit,
    concurrency: opts.concurrency,
    batchSize: opts.batchSize,
    filter: opts.filter,
    rootPathOverride: opts.root,
    manifestPath: opts.manifest,
    onlySlugs,
    skipSlugs,
    onProgress: logProgress,
  });

  console.log();
  console.log(`${GREEN}Revalidation complete.${RESET} Run: ${BOLD}${result.runId}${RESET}`);
  console.log(
    `  ${GREEN}TP: ${result.truePositives}${RESET}  ${RED}FP: ${result.falsePositives}${RESET}  ${CYAN}Fixed: ${result.fixed}${RESET}  ${YELLOW}Uncertain: ${result.uncertain}${RESET}`,
  );
}

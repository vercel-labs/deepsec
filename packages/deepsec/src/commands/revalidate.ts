import type { Severity } from "@deepsec/core";
import { readProjectConfig } from "@deepsec/core";
import { revalidate } from "@deepsec/processor";
import { buildAgentConfig } from "../agent-config.js";
import { defaultModelForAgent } from "../agent-defaults.js";
import { BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW } from "../formatters.js";
import { applyConfiguredModelRoute, assertAgentCredential } from "../preflight.js";
import { renderQuotaMessage } from "../quota-message.js";
import { resolveAgentType } from "../resolve-agent-type.js";
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
        } else if (ap.type === "thinking") {
          // Reconciliation / id-repair / split-retry status lives on
          // "thinking" progress events — surface it dimly.
          console.log(`  ${DIM}${ap.message}${RESET}`);
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
  thinkingLevel?: string;
  aiProvider?: string;
  aiBaseUrl?: string;
  aiApiKeyEnv?: string;
  aiHeader?: string[];
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
  const agentType = resolveAgentType(opts.agent);
  const model = opts.model ?? defaultModelForAgent(agentType);
  const minSeverity = opts.minSeverity as Severity | undefined;
  const onlySlugs = parseCsv(opts.onlySlugs);
  const skipSlugs = parseCsv(opts.skipSlugs);

  const resolvedRoute =
    !opts.aiApiKeyEnv && !opts.aiBaseUrl ? await applyConfiguredModelRoute(agentType) : undefined;
  const agentConfig = buildAgentConfig({ ...opts, model, modelRoute: resolvedRoute?.route });
  assertAgentCredential(agentType, { aiApiKeyEnv: opts.aiApiKeyEnv });

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
    config: agentConfig,
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
  const dupeStr =
    result.duplicates > 0 || result.duplicatesRejected > 0
      ? `  ${DIM}Dupe: ${result.duplicates}${result.duplicatesRejected ? ` (${result.duplicatesRejected} rejected)` : ""}${RESET}`
      : "";
  console.log(
    `  ${GREEN}TP: ${result.truePositives}${RESET}  ${RED}FP: ${result.falsePositives}${RESET}  ${CYAN}Fixed: ${result.fixed}${RESET}  ${YELLOW}Uncertain: ${result.uncertain}${RESET}${dupeStr}`,
  );
  console.log(
    `  ${DIM}Persisted ${result.revalidated}/${result.requested} requested verdicts${RESET}`,
  );
  if (result.quotaExhausted) {
    console.log(
      renderQuotaMessage({
        source: result.quotaExhausted.source,
        rawMessage: result.quotaExhausted.rawMessage,
        command: "revalidate",
        projectId,
      }),
    );
    process.exit(1);
  }
  if (result.unresolved.length > 0) {
    console.log();
    console.log(
      `${RED}${result.unresolved.length} finding(s) did not receive a verdict after repair and split retries:${RESET}`,
    );
    for (const u of result.unresolved.slice(0, 20)) {
      console.log(`  ${RED}-${RESET} ${u.filePath} ${DIM}${u.findingId}${RESET} "${u.title}"`);
    }
    if (result.unresolved.length > 20) {
      console.log(`  ${DIM}… and ${result.unresolved.length - 20} more${RESET}`);
    }
    console.log(
      `  ${DIM}Raw responses + reconciliation diagnostics: data/${projectId}/revalidation/${result.runId}/${RESET}`,
    );
    process.exit(1);
  }
  if (result.revalidated === 0 && !opts.force) {
    console.log(
      `  ${DIM}Tip: pass ${RESET}${BOLD}--force${RESET}${DIM} to revalidate findings again (e.g. after fixes).${RESET}`,
    );
  }
}

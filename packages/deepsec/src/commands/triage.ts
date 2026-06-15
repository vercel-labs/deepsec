import type { Severity } from "@deepsec/core";
import { readProjectConfig } from "@deepsec/core";
import { triage } from "@deepsec/processor";
import { defaultModelForAgent } from "../agent-defaults.js";
import { BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW } from "../formatters.js";
import { assertAgentCredential } from "../preflight.js";
import { resolveAgentType } from "../resolve-agent-type.js";
import { resolveProjectId } from "../resolve-project-id.js";

export async function triageCommand(opts: {
  projectId?: string;
  severity?: string;
  agent?: string;
  force?: boolean;
  limit?: number;
  concurrency?: number;
  model?: string;
}) {
  const projectId = resolveProjectId(opts.projectId);
  readProjectConfig(projectId);
  const severity = (opts.severity ?? "MEDIUM") as Severity;
  const agentType = resolveAgentType(opts.agent ?? "claude");
  if (agentType !== "claude-agent-sdk" && agentType !== "cursor") {
    throw new Error("triage currently supports only --agent claude or --agent cursor");
  }
  const model =
    opts.model ?? (agentType === "cursor" ? defaultModelForAgent("cursor") : "claude-sonnet-4-6");

  assertAgentCredential(agentType);

  console.log(
    `${BOLD}Triaging${RESET} ${severity} findings for project ${BOLD}${projectId}${RESET}`,
  );
  console.log(`  Agent: ${agentType} (${model})`);
  console.log(`  ${DIM}Lightweight path — triage uses finding text only.${RESET}`);
  if (opts.force) console.log(`  ${YELLOW}Force re-triaging already-triaged findings${RESET}`);
  console.log();

  const result = await triage({
    projectId,
    severity,
    agentType,
    force: opts.force,
    limit: opts.limit,
    concurrency: opts.concurrency,
    model,
    onProgress(progress) {
      switch (progress.type) {
        case "batch_started":
          console.log(`${BOLD}${progress.message}${RESET}`);
          break;
        case "batch_complete":
          console.log(`  ${DIM}${progress.message}${RESET}`);
          break;
        case "all_complete":
          console.log(`\n${DIM}${progress.message}${RESET}`);
          break;
      }
    },
  });

  console.log();
  console.log(`${GREEN}Triage complete.${RESET}`);
  console.log(
    `  ${RED}P0: ${result.p0}${RESET}  ${YELLOW}P1: ${result.p1}${RESET}  ${CYAN}P2: ${result.p2}${RESET}  ${DIM}skip: ${result.skip}${RESET}`,
  );
}

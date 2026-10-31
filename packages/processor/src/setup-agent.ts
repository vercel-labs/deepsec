import { runClaudeSetupTask } from "./agents/claude-agent-sdk.js";
import { runCodexSetupTask } from "./agents/codex-sdk.js";
import { runPiSetupTask } from "./agents/pi-sdk.js";
import type { SetupTaskParams } from "./agents/types.js";

export interface RunSetupTaskParams extends SetupTaskParams {
  agentType: string;
}

/** Run one schema-oriented, read-only repository task through a built-in agent. */
export async function runSetupTask(params: RunSetupTaskParams): Promise<string> {
  switch (params.agentType) {
    case "codex":
      return runCodexSetupTask(params);
    case "claude":
    case "claude-agent-sdk":
      return runClaudeSetupTask(params);
    case "pi":
      return runPiSetupTask(params);
    default:
      throw new Error(
        `Agent "${params.agentType}" does not support automated setup. Use codex, claude, or pi.`,
      );
  }
}

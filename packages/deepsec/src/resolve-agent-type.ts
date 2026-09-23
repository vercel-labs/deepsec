import { getConfig } from "@deepsec/core";

/**
 * Resolve the agent backend from CLI input or the loaded config.
 *
 * Precedence:
 *   1. The `--agent` value the user passed (always wins).
 *   2. `defaultAgent` from deepsec.config.ts.
 *   3. `codex`.
 */
export function resolveAgentType(provided: string | undefined): string {
  const resolved = provided ?? getConfig()?.defaultAgent ?? "codex";
  if (resolved === "claude") return "claude-agent-sdk";
  if (resolved === "grok-build") return "grok";
  return resolved;
}

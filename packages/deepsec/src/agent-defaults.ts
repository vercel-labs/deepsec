/**
 * Per-backend default models. Used when --model is not explicitly set.
 * Keep in sync with the DEFAULT_MODEL constants in each agent plugin.
 */
export function defaultModelForAgent(agentType: string): string {
  switch (agentType) {
    case "codex":
      return "gpt-5.5";
    case "copilot-rotate":
      return "gpt-5.5";
    default:
      return "claude-opus-4-7";
  }
}

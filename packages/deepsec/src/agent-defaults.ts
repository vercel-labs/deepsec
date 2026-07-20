/**
 * Per-backend default models. Used when --model is not explicitly set.
 * Keep in sync with the DEFAULT_MODEL constants in each agent plugin.
 */
export function defaultModelForAgent(agentType: string): string {
  switch (agentType) {
    case "codex":
      return "gpt-5.5";
    case "pi":
      return "zai/glm-5.2";
    case "opencode":
      return "anthropic/claude-opus-4-8";
    default:
      return "claude-opus-4-8";
  }
}

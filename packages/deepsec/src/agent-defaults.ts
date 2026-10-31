import { getConfig } from "@deepsec/core";

/**
 * Per-backend default models. Used when --model is not explicitly set.
 * Keep in sync with the DEFAULT_MODEL constants in each agent plugin.
 */
export function defaultModelForAgent(agentType: string): string {
  const config = getConfig();
  const configuredAgent =
    config?.defaultAgent === "claude" ? "claude-agent-sdk" : config?.defaultAgent;
  if (config?.defaultModel && configuredAgent === agentType) return config.defaultModel;
  switch (agentType) {
    case "codex":
      return "gpt-5.5";
    case "pi":
      return "zai/glm-5.2";
    default:
      return "claude-opus-4-8";
  }
}

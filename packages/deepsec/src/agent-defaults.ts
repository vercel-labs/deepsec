import { ATLAS_DEFAULT_MODEL, ATLAS_PROVIDER } from "./atlas-provider.js";

/**
 * Per-backend default models. Used when --model is not explicitly set.
 * Keep in sync with the DEFAULT_MODEL constants in each agent plugin.
 */
export function defaultModelForAgent(agentType: string, aiProvider?: string): string {
  switch (agentType) {
    case "codex":
      return "gpt-5.5";
    case "pi":
      return aiProvider === ATLAS_PROVIDER ? ATLAS_DEFAULT_MODEL : "zai/glm-5.2";
    default:
      return "claude-opus-4-8";
  }
}

import { describe, expect, it } from "vitest";
import { defaultModelForAgent } from "../agent-defaults.js";

describe("defaultModelForAgent", () => {
  it("returns the backend-specific default models", () => {
    expect(defaultModelForAgent("codex")).toBe("gpt-5.5");
    expect(defaultModelForAgent("pi")).toBe("zai/glm-5.2");
    expect(defaultModelForAgent("opencode")).toBe("anthropic/claude-opus-4-8");
    expect(defaultModelForAgent("claude-agent-sdk")).toBe("claude-opus-4-8");
  });
});

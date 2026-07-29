import { describe, expect, it } from "vitest";
import { buildAgentConfig } from "../agent-config.js";

describe("buildAgentConfig", () => {
  it("applies the Fireworks Kimi K3 provider preset", () => {
    expect(
      buildAgentConfig({
        model: "fireworks/accounts/fireworks/models/kimi-k3",
      }),
    ).toMatchObject({
      model: "fireworks/accounts/fireworks/models/kimi-k3",
      aiProvider: "fireworks",
      aiBaseUrl: "https://api.fireworks.ai/inference/v1",
      aiBaseUrlFromPreset: true,
      aiApiKeyEnv: "FIREWORKS_API_KEY",
    });
  });

  it("lets explicit Fireworks overrides replace the Kimi K3 preset defaults", () => {
    expect(
      buildAgentConfig({
        model: "fireworks/accounts/fireworks/models/kimi-k3",
        aiBaseUrl: "https://fireworks.example.test/v1",
        aiApiKeyEnv: "CUSTOM_FIREWORKS_KEY",
        aiHeader: ["x-fireworks-account=test"],
      }),
    ).toMatchObject({
      aiProvider: "fireworks",
      aiBaseUrl: "https://fireworks.example.test/v1",
      aiApiKeyEnv: "CUSTOM_FIREWORKS_KEY",
      aiHeaders: { "x-fireworks-account": "test" },
    });
    expect(
      buildAgentConfig({
        model: "fireworks/accounts/fireworks/models/kimi-k3",
        aiBaseUrl: "https://fireworks.example.test/v1",
      }),
    ).not.toHaveProperty("aiBaseUrlFromPreset");
  });

  it("does not apply Fireworks defaults to other models", () => {
    const config = buildAgentConfig({ model: "fireworks/accounts/fireworks/models/glm-5p2" });
    expect(config).not.toHaveProperty("aiBaseUrl");
    expect(config).not.toHaveProperty("aiApiKeyEnv");
  });

  it("does not silently apply Fireworks routing to a conflicting explicit provider", () => {
    expect(
      buildAgentConfig({
        model: "fireworks/accounts/fireworks/models/kimi-k3",
        aiProvider: "custom",
      }),
    ).toEqual({
      model: "fireworks/accounts/fireworks/models/kimi-k3",
      aiProvider: "custom",
    });
  });

  it("infers the provider for Pi custom API key env overrides from provider/model", () => {
    expect(
      buildAgentConfig({
        model: "openai/gpt-5.5",
        aiApiKeyEnv: "MARTIAN_API_KEY",
      }),
    ).toMatchObject({
      model: "openai/gpt-5.5",
      aiProvider: "openai",
      aiApiKeyEnv: "MARTIAN_API_KEY",
    });
  });

  it("requires a provider when provider override flags are used with a bare model", () => {
    expect(() =>
      buildAgentConfig({
        model: "gpt-5.5",
        aiApiKeyEnv: "MARTIAN_API_KEY",
      }),
    ).toThrow(/--ai-provider/);
  });

  it("maps --thinking-level to both harness config keys", () => {
    expect(
      buildAgentConfig({
        model: "openai/gpt-5.5",
        thinkingLevel: "medium",
      }),
    ).toMatchObject({
      thinkingLevel: "medium",
      reasoningEffort: "medium",
    });
  });

  it("omits thinking keys when --thinking-level is not given", () => {
    const config = buildAgentConfig({ model: "openai/gpt-5.5" });
    expect(config).not.toHaveProperty("thinkingLevel");
    expect(config).not.toHaveProperty("reasoningEffort");
  });

  it("rejects unknown thinking levels", () => {
    expect(() =>
      buildAgentConfig({
        model: "openai/gpt-5.5",
        thinkingLevel: "ultra",
      }),
    ).toThrow(/--thinking-level must be one of/);
  });

  it("parses repeatable AI headers", () => {
    expect(
      buildAgentConfig({
        model: "openai/gpt-5.5",
        aiHeader: ["x-test=one", "x-other=two"],
      }),
    ).toMatchObject({
      aiProvider: "openai",
      aiHeaders: { "x-test": "one", "x-other": "two" },
    });
  });
});

import { describe, expect, it } from "vitest";
import { buildAgentConfig } from "../agent-config.js";

describe("buildAgentConfig", () => {
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

  it("applies Atlas Cloud defaults for the atlas provider", () => {
    expect(
      buildAgentConfig({
        model: "atlas/deepseek-ai/deepseek-v4-pro",
        aiProvider: "atlas",
      }),
    ).toMatchObject({
      aiProvider: "atlas",
      aiBaseUrl: "https://api.atlascloud.ai/v1",
      aiApiKeyEnv: "ATLASCLOUD_API_KEY",
    });
  });

  it("preserves explicit Atlas Cloud provider overrides", () => {
    expect(
      buildAgentConfig({
        model: "atlas/custom-model",
        aiProvider: "atlas",
        aiBaseUrl: "https://atlas.example/v1",
        aiApiKeyEnv: "CUSTOM_ATLAS_KEY",
      }),
    ).toMatchObject({
      aiBaseUrl: "https://atlas.example/v1",
      aiApiKeyEnv: "CUSTOM_ATLAS_KEY",
    });
  });
});

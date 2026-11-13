import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { defineConfig, setLoadedConfig } from "@deepsec/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buildAgentConfig } from "../agent-config.js";

describe("buildAgentConfig", () => {
  afterEach(() => setLoadedConfig(defineConfig({ projects: [] })));

  it("infers the provider for Pi custom API key env overrides from provider/model", () => {
    expect(
      buildAgentConfig({
        agentType: "pi",
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
      buildAgentConfig({ agentType: "pi", model: "gpt-5.5", aiApiKeyEnv: "MARTIAN_API_KEY" }),
    ).toThrow(/--ai-provider/);
  });

  it("propagates a persisted custom route into Pi runtime configuration", () => {
    expect(
      buildAgentConfig({
        agentType: "pi",
        model: "acme/security-model",
        modelRoute: {
          mode: "custom",
          provider: "acme",
          baseUrl: "https://models.acme.test/v1",
          apiKeyEnv: "ACME_MODEL_KEY",
          credentialHeader: { name: "x-api-key", scheme: "raw" },
        },
      }),
    ).toMatchObject({
      aiProvider: "acme",
      aiBaseUrl: "https://models.acme.test/v1",
      aiApiKeyEnv: "ACME_MODEL_KEY",
      aiCredentialHeader: { name: "x-api-key", scheme: "raw" },
    });
  });

  it("maps --thinking-level to both harness config keys", () => {
    expect(
      buildAgentConfig({ agentType: "pi", model: "openai/gpt-5.5", thinkingLevel: "medium" }),
    ).toMatchObject({
      thinkingLevel: "medium",
      reasoningEffort: "medium",
    });
  });

  it("omits thinking keys when --thinking-level is not given", () => {
    const config = buildAgentConfig({ agentType: "pi", model: "openai/gpt-5.5" });
    expect(config).not.toHaveProperty("thinkingLevel");
    expect(config).not.toHaveProperty("reasoningEffort");
  });

  it("uses the thinking level persisted during setup", () => {
    setLoadedConfig(defineConfig({ projects: [], defaultThinkingLevel: "high" }));
    expect(buildAgentConfig({ agentType: "pi", model: "xai/grok-4.5" })).toMatchObject({
      thinkingLevel: "high",
      reasoningEffort: "high",
    });
  });

  it("rejects unknown thinking levels", () => {
    expect(() =>
      buildAgentConfig({ agentType: "pi", model: "openai/gpt-5.5", thinkingLevel: "ultra" }),
    ).toThrow(/--thinking-level must be one of/);
  });

  it("parses repeatable AI headers", () => {
    expect(
      buildAgentConfig({
        agentType: "pi",
        model: "openai/gpt-5.5",
        aiHeader: ["x-test=one", "x-other=two"],
      }),
    ).toMatchObject({
      aiProvider: "openai",
      aiHeaders: { "x-test": "one", "x-other": "two" },
    });
  });
});

describe("buildAgentConfig cyberAccessProgram", () => {
  beforeEach(() => {
    const codexHome = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-codex-home-"));
    fs.writeFileSync(path.join(codexHome, "auth.json"), "{}");
    vi.stubEnv("CODEX_HOME", codexHome);
    vi.stubEnv("OPENAI_API_KEY", "");
    vi.stubEnv("ANTHROPIC_AUTH_TOKEN", "");
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    setLoadedConfig(defineConfig({ projects: [] }));
  });

  it("forwards the CLI value for codex on a subscription login", () => {
    expect(
      buildAgentConfig({ agentType: "codex", cyberAccessProgram: "daybreak_blue" })
        .cyberAccessProgram,
    ).toBe("daybreak_blue");
  });

  it("falls back to codex.cyberAccessProgram from deepsec.config.ts", () => {
    setLoadedConfig(defineConfig({ projects: [], codex: { cyberAccessProgram: "daybreak_red" } }));
    expect(buildAgentConfig({ agentType: "codex" }).cyberAccessProgram).toBe("daybreak_red");
  });

  it("ignores the config value when another agent runs", () => {
    setLoadedConfig(defineConfig({ projects: [], codex: { cyberAccessProgram: "daybreak_blue" } }));
    expect(buildAgentConfig({ agentType: "claude-agent-sdk" })).not.toHaveProperty(
      "cyberAccessProgram",
    );
  });

  it("rejects the CLI flag for non-codex agents", () => {
    expect(() =>
      buildAgentConfig({ agentType: "pi", cyberAccessProgram: "daybreak_blue" }),
    ).toThrow("--cyber-access-program requires --agent codex");
  });

  it("rejects unknown programs", () => {
    expect(() =>
      buildAgentConfig({ agentType: "codex", cyberAccessProgram: "daybreak_purple" }),
    ).toThrow(/must be one of standard, daybreak_blue, daybreak_red/);
  });

  it("rejects gateway mode, whose custom provider cannot carry the program", () => {
    vi.stubEnv("OPENAI_API_KEY", "sk-test");
    expect(() =>
      buildAgentConfig({ agentType: "codex", cyberAccessProgram: "daybreak_blue" }),
    ).toThrow(/only works with Codex subscription auth/);
  });
});

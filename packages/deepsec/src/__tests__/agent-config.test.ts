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

  it("records the saved model-auth mode for agent backends", () => {
    setLoadedConfig(defineConfig({ projects: [], ai: { mode: "local", provider: "local" } }));
    expect(buildAgentConfig({ agentType: "codex", model: "gpt-5.5" })).toMatchObject({
      modelAuth: "local",
    });
    expect(
      buildAgentConfig({
        agentType: "codex",
        model: "gpt-5.5",
        modelRoute: { mode: "direct", provider: "openai", apiKeyEnv: "OPENAI_API_KEY" },
      }),
    ).toMatchObject({ modelAuth: "direct" });
  });

  it("lets an explicit per-run route override a saved local mode", () => {
    setLoadedConfig(defineConfig({ projects: [], ai: { mode: "local", provider: "local" } }));
    expect(
      buildAgentConfig({
        agentType: "codex",
        model: "gpt-5.5",
        modelRoute: { mode: "gateway", provider: "vercel" },
      }),
    ).toMatchObject({ modelAuth: "gateway" });
  });

  it("does not inherit the saved local mode when --ai-* overrides are present", () => {
    setLoadedConfig(defineConfig({ projects: [], ai: { mode: "local", provider: "local" } }));
    expect(
      buildAgentConfig({
        agentType: "codex",
        model: "openai/gpt-5.5",
        aiApiKeyEnv: "MY_MODEL_KEY",
      }),
    ).not.toHaveProperty("modelAuth");
    expect(
      buildAgentConfig({
        agentType: "codex",
        model: "openai/gpt-5.5",
        aiBaseUrl: "https://my-gateway.test/v1",
      }),
    ).not.toHaveProperty("modelAuth");
    expect(buildAgentConfig({ agentType: "codex", model: "gpt-5.5" })).toMatchObject({
      modelAuth: "local",
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

  it("maps a per-run --ai-credential-header to the Pi runtime config", () => {
    expect(
      buildAgentConfig({
        agentType: "pi",
        model: "openai/gpt-5.5",
        aiApiKeyEnv: "MARTIAN_API_KEY",
        aiCredentialHeader: "x-api-key:raw",
      }),
    ).toMatchObject({
      aiProvider: "openai",
      aiApiKeyEnv: "MARTIAN_API_KEY",
      aiCredentialHeader: { name: "x-api-key", scheme: "raw" },
    });
  });

  it("defaults a per-run authorization header to the bearer scheme", () => {
    expect(
      buildAgentConfig({
        agentType: "pi",
        model: "acme/security-model",
        aiApiKeyEnv: "ACME_MODEL_KEY",
        aiCredentialHeader: "authorization",
      }),
    ).toMatchObject({
      aiCredentialHeader: { name: "authorization", scheme: "bearer" },
    });
  });

  it("rejects an unknown per-run credential header scheme", () => {
    expect(() =>
      buildAgentConfig({
        agentType: "pi",
        model: "acme/security-model",
        aiApiKeyEnv: "ACME_MODEL_KEY",
        aiCredentialHeader: "x-api-key:basic",
      }),
    ).toThrow(/scheme must be bearer or raw/);
  });
});

describe("buildAgentConfig cyberAccessProgram", () => {
  let codexHome: string;
  let emptyHome: string;
  const created: string[] = [];

  function tempDir(prefix: string): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
    created.push(dir);
    return dir;
  }

  beforeEach(() => {
    codexHome = tempDir("deepsec-codex-home-");
    fs.writeFileSync(path.join(codexHome, "auth.json"), "{}");
    emptyHome = tempDir("deepsec-empty-home-");
    vi.stubEnv("CODEX_HOME", codexHome);
    // os.homedir()/.codex is the fallback for the Codex login; point it at an
    // empty directory so the "no login" cases are hermetic on dev machines.
    vi.stubEnv("HOME", emptyHome);
    vi.stubEnv("USERPROFILE", emptyHome);
    vi.stubEnv("OPENAI_API_KEY", "");
    vi.stubEnv("ANTHROPIC_AUTH_TOKEN", "");
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    setLoadedConfig(defineConfig({ projects: [] }));
    for (const dir of created.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
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

  it("ignores the config value in gateway mode", () => {
    vi.stubEnv("OPENAI_API_KEY", "sk-test");
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    setLoadedConfig(defineConfig({ projects: [], codex: { cyberAccessProgram: "daybreak_blue" } }));
    expect(buildAgentConfig({ agentType: "codex" })).not.toHaveProperty("cyberAccessProgram");
    expect(warn).toHaveBeenCalledWith(
      "Ignoring codex.cyberAccessProgram from deepsec.config.ts: this run uses gateway auth because OPENAI_API_KEY or ANTHROPIC_AUTH_TOKEN is set.",
    );
    warn.mockRestore();
  });

  it("rejects gateway mode, whose custom provider cannot carry the program", () => {
    vi.stubEnv("OPENAI_API_KEY", "sk-test");
    expect(() =>
      buildAgentConfig({ agentType: "codex", cyberAccessProgram: "daybreak_blue" }),
    ).toThrow(/only works with Codex subscription auth/);
  });

  // A saved local route is the user choosing Codex subscription auth. Ambient
  // keys exported for other tools must not override that choice, so Cyber
  // Access Program selection must follow the same route-aware predicate as the
  // Codex backend instead of being vetoed by the ambient key.
  it("keeps --cyber-access-program on a saved local route with an ambient API key", () => {
    setLoadedConfig(defineConfig({ projects: [], ai: { mode: "local", provider: "local" } }));
    vi.stubEnv("OPENAI_API_KEY", "sk-ambient-for-other-tools");
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

    expect(
      buildAgentConfig({ agentType: "codex", cyberAccessProgram: "daybreak_blue" }),
    ).toMatchObject({ cyberAccessProgram: "daybreak_blue", modelAuth: "local" });
    expect(warn).not.toHaveBeenCalled();
    warn.mockRestore();
  });

  it("keeps codex.cyberAccessProgram from deepsec.config.ts on a saved local route with an ambient API key", () => {
    setLoadedConfig(
      defineConfig({
        projects: [],
        ai: { mode: "local", provider: "local" },
        codex: { cyberAccessProgram: "daybreak_red" },
      }),
    );
    vi.stubEnv("OPENAI_API_KEY", "sk-ambient-for-other-tools");
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

    expect(buildAgentConfig({ agentType: "codex" })).toMatchObject({
      cyberAccessProgram: "daybreak_red",
      modelAuth: "local",
    });
    expect(warn).not.toHaveBeenCalled();
    warn.mockRestore();
  });

  it("drops the config program when a saved local route has no Codex login", () => {
    vi.stubEnv("CODEX_HOME", emptyHome);
    vi.stubEnv("OPENAI_API_KEY", "sk-ambient-for-other-tools");
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    setLoadedConfig(
      defineConfig({
        projects: [],
        ai: { mode: "local", provider: "local" },
        codex: { cyberAccessProgram: "daybreak_blue" },
      }),
    );

    expect(buildAgentConfig({ agentType: "codex" })).not.toHaveProperty("cyberAccessProgram");
    expect(warn).toHaveBeenCalledWith(
      "Ignoring codex.cyberAccessProgram from deepsec.config.ts: the saved local-subscription route has no Codex login, so the run requires `codex login`.",
    );
    warn.mockRestore();
  });

  it("points a saved local route without a Codex login at codex login, not at unsetting keys", () => {
    vi.stubEnv("CODEX_HOME", emptyHome);
    setLoadedConfig(defineConfig({ projects: [], ai: { mode: "local", provider: "local" } }));

    let message = "";
    try {
      buildAgentConfig({ agentType: "codex", cyberAccessProgram: "daybreak_blue" });
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toContain("only works with Codex subscription auth");
    expect(message).toContain("no Codex login was found");
    expect(message).toContain("codex login");
    expect(message).not.toContain("fall back");
    expect(message).not.toContain("unset OPENAI_API_KEY");
  });
});

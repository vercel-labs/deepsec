import { defineConfig, setLoadedConfig } from "@deepsec/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resolveRunAgentConfig } from "../run-route.js";

// `process` / `revalidate` resolve the model route in a fresh process. A
// one-run `--model-auth` override must win over the saved route without
// editing deepsec.config.ts.
describe("resolveRunAgentConfig", () => {
  beforeEach(() => {
    vi.stubEnv("AI_GATEWAY_API_KEY", "");
    vi.stubEnv("OPENAI_API_KEY", "");
    vi.stubEnv("ANTHROPIC_AUTH_TOKEN", "");
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    // Routes resolved here apply env vars directly (OPENAI_BASE_URL, ...);
    // remove them so later cases start from the stubbed-empty baseline.
    for (const name of [
      "ACME_MODEL_KEY",
      "AI_GATEWAY_API_KEY",
      "ANTHROPIC_API_KEY",
      "ANTHROPIC_AUTH_TOKEN",
      "ANTHROPIC_BASE_URL",
      "DEEPSEC_PI_AI_BASE_URL",
      "OPENAI_API_KEY",
      "OPENAI_BASE_URL",
      "VERCEL_OIDC_TOKEN",
    ]) {
      delete process.env[name];
    }
    setLoadedConfig(defineConfig({ projects: [] }));
  });

  it("uses the saved local route when no override is given", async () => {
    setLoadedConfig(defineConfig({ projects: [], ai: { mode: "local", provider: "local" } }));

    const { agentConfig, explicitRoute } = await resolveRunAgentConfig({
      agentType: "codex",
      model: "gpt-5.5",
    });

    expect(agentConfig).toMatchObject({ modelAuth: "local" });
    expect(explicitRoute).toBeUndefined();
  });

  it("lets --model-auth gateway override a saved local route for one run", async () => {
    vi.stubEnv("AI_GATEWAY_API_KEY", "vck_run");
    setLoadedConfig(defineConfig({ projects: [], ai: { mode: "local", provider: "local" } }));

    const { agentConfig, explicitRoute } = await resolveRunAgentConfig({
      agentType: "codex",
      model: "gpt-5.5",
      modelAuth: "gateway",
    });

    expect(explicitRoute).toEqual({ mode: "gateway", provider: "vercel" });
    expect(agentConfig).toMatchObject({ modelAuth: "gateway" });
    expect(process.env.OPENAI_API_KEY).toBe("vck_run");
  });

  it("lets --model-auth local override a saved gateway route for one run", async () => {
    setLoadedConfig(defineConfig({ projects: [], ai: { mode: "gateway", provider: "vercel" } }));

    const { agentConfig, explicitRoute } = await resolveRunAgentConfig({
      agentType: "claude-agent-sdk",
      model: "claude-opus-4-8",
      modelAuth: "local",
    });

    expect(explicitRoute).toEqual({ mode: "local", provider: "local" });
    expect(agentConfig).toMatchObject({ modelAuth: "local" });
  });

  it("resolves a complete custom route for Pi", async () => {
    vi.stubEnv("ACME_MODEL_KEY", "acme-secret");

    const { agentConfig, explicitRoute } = await resolveRunAgentConfig({
      agentType: "pi",
      model: "acme/security-model",
      modelAuth: "custom",
      aiProvider: "acme",
      aiBaseUrl: "https://models.acme.test/v1",
      aiApiKeyEnv: "ACME_MODEL_KEY",
      aiCredentialHeader: "x-api-key:raw",
    });

    expect(explicitRoute).toEqual({
      mode: "custom",
      provider: "acme",
      apiKeyEnv: "ACME_MODEL_KEY",
      baseUrl: "https://models.acme.test/v1",
      credentialHeader: { name: "x-api-key", scheme: "raw" },
    });
    expect(agentConfig).toMatchObject({
      aiProvider: "acme",
      aiBaseUrl: "https://models.acme.test/v1",
      aiApiKeyEnv: "ACME_MODEL_KEY",
      aiCredentialHeader: { name: "x-api-key", scheme: "raw" },
      modelAuth: "custom",
    });
  });

  it("defaults an authorization custom header to the bearer scheme", async () => {
    vi.stubEnv("ACME_MODEL_KEY", "acme-secret");

    const { explicitRoute } = await resolveRunAgentConfig({
      agentType: "pi",
      model: "acme/security-model",
      modelAuth: "custom",
      aiProvider: "acme",
      aiBaseUrl: "https://models.acme.test/v1",
      aiApiKeyEnv: "ACME_MODEL_KEY",
      aiCredentialHeader: "authorization",
    });

    expect(explicitRoute?.credentialHeader).toEqual({ name: "authorization", scheme: "bearer" });
  });

  it("points a custom route without --ai-credential-header at the command flag", async () => {
    await expect(
      resolveRunAgentConfig({
        agentType: "pi",
        model: "acme/security-model",
        modelAuth: "custom",
        aiProvider: "acme",
        aiBaseUrl: "https://models.acme.test/v1",
        aiApiKeyEnv: "ACME_MODEL_KEY",
      }),
    ).rejects.toThrow(/--ai-credential-header/);
  });

  it("rejects a custom route for non-Pi agents", async () => {
    vi.stubEnv("ACME_MODEL_KEY", "acme-secret");

    await expect(
      resolveRunAgentConfig({
        agentType: "codex",
        model: "gpt-5.5",
        modelAuth: "custom",
        aiProvider: "acme",
        aiBaseUrl: "https://models.acme.test/v1",
        aiApiKeyEnv: "ACME_MODEL_KEY",
        aiCredentialHeader: "x-api-key:raw",
      }),
    ).rejects.toThrow(/Custom model routes require --agent pi/);
  });

  // A one-run direct route may omit --ai-provider: the command's resolved
  // agent type (including defaultAgent from deepsec.config.ts) supplies it.
  it("infers an OpenAI direct route from the resolved Codex agent", async () => {
    vi.stubEnv("OPENAI_API_KEY", "sk-run");

    const { explicitRoute } = await resolveRunAgentConfig({
      agentType: "codex",
      model: "gpt-5.5",
      modelAuth: "direct",
    });

    expect(explicitRoute).toMatchObject({
      mode: "direct",
      provider: "openai",
      apiKeyEnv: "OPENAI_API_KEY",
    });
  });

  it("infers an Anthropic direct route from the resolved Claude agent", async () => {
    vi.stubEnv("ANTHROPIC_API_KEY", "sk-ant-run");

    const { explicitRoute } = await resolveRunAgentConfig({
      agentType: "claude-agent-sdk",
      model: "claude-opus-4-8",
      modelAuth: "direct",
    });

    expect(explicitRoute).toMatchObject({
      mode: "direct",
      provider: "anthropic",
      apiKeyEnv: "ANTHROPIC_API_KEY",
    });
  });
});

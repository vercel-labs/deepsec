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
});

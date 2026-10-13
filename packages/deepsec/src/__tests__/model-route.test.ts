import { describe, expect, it, vi } from "vitest";
import { applyResolvedModelRoute, resolveModelRoute } from "../auth/model-route.js";

describe("resolveModelRoute", () => {
  it("refuses to resolve a local-subscription route to a brokered credential", async () => {
    await expect(
      resolveModelRoute({ mode: "local", provider: "local" }, { agentType: "codex", env: {} }),
    ).rejects.toThrow(/machine-wide agent logins/);
  });

  it("still rejects an explicitly selected route that is incompatible with the harness", async () => {
    await expect(
      resolveModelRoute(
        { mode: "direct", provider: "openai" },
        { agentType: "claude-agent-sdk", env: { OPENAI_API_KEY: "secret" } },
      ),
    ).rejects.toThrow(/not compatible with --agent claude/);
  });

  it("uses OIDC only for an explicitly selected gateway route", async () => {
    const getOidcToken = vi.fn(async () => "oidc-secret");
    const resolved = await resolveModelRoute(
      { mode: "gateway", provider: "vercel" },
      { agentType: "codex", env: { VERCEL_OIDC_TOKEN: "jwt" }, getOidcToken },
    );
    expect(getOidcToken).toHaveBeenCalledOnce();
    expect(resolved.environment.OPENAI_API_KEY).toBe("oidc-secret");
    expect(resolved.broker.host).toBe("ai-gateway.vercel.sh");
    expect(resolved.broker.placeholderEnv).toBe("AI_GATEWAY_API_KEY");
  });

  it("does not fall back from a selected direct route to ambient Gateway", async () => {
    await expect(
      resolveModelRoute(
        { mode: "direct", provider: "anthropic", apiKeyEnv: "MY_ANTHROPIC_KEY" },
        {
          agentType: "claude-agent-sdk",
          env: { AI_GATEWAY_API_KEY: "must-not-win", VERCEL_OIDC_TOKEN: "also-no" },
        },
      ),
    ).rejects.toThrow(/MY_ANTHROPIC_KEY/);
  });

  it("supports a provider-specific raw custom header", async () => {
    const resolved = await resolveModelRoute(
      {
        mode: "custom",
        provider: "martian",
        apiKeyEnv: "MARTIAN_KEY",
        baseUrl: "https://api.martian.example/v1",
        credentialHeader: { name: "X-Api-Key", scheme: "raw" },
      },
      { agentType: "pi", env: { MARTIAN_KEY: "secret" } },
    );
    expect(resolved.broker).toEqual({
      host: "api.martian.example",
      placeholderEnv: "MARTIAN_KEY",
      header: { name: "x-api-key", value: "secret" },
    });
  });

  it("uses x-api-key for direct Anthropic credentials", async () => {
    const resolved = await resolveModelRoute(
      { mode: "direct", provider: "anthropic" },
      { agentType: "claude-agent-sdk", env: { ANTHROPIC_API_KEY: "sk-ant" } },
    );
    expect(resolved.environment.ANTHROPIC_API_KEY).toBe("sk-ant");
    expect(resolved.broker.placeholderEnv).toBe("ANTHROPIC_API_KEY");
    expect(resolved.broker.header).toEqual({ name: "x-api-key", value: "sk-ant" });
  });

  it("removes a stale Gateway bearer token for direct Anthropic", async () => {
    const env = {
      ANTHROPIC_API_KEY: "sk-ant",
      ANTHROPIC_AUTH_TOKEN: "stale-gateway-token",
      ANTHROPIC_BASE_URL: "https://ai-gateway.vercel.sh",
    };
    const resolved = await resolveModelRoute(
      { mode: "direct", provider: "anthropic" },
      { agentType: "claude-agent-sdk", env },
    );
    applyResolvedModelRoute(resolved, env);
    expect(env.ANTHROPIC_AUTH_TOKEN).toBeUndefined();
    expect(env.ANTHROPIC_BASE_URL).toBe("https://api.anthropic.com");
  });

  it("preserves the in-sandbox Claude proxy when reapplying a route", async () => {
    const env = {
      AI_GATEWAY_API_KEY: "brokered-placeholder",
      ANTHROPIC_BASE_URL: "http://127.0.0.1:8787",
      ANTHROPIC_UPSTREAM_BASE_URL: "https://ai-gateway.vercel.sh",
    };
    const resolved = await resolveModelRoute(
      { mode: "gateway", provider: "vercel" },
      { agentType: "claude-agent-sdk", env },
    );
    applyResolvedModelRoute(resolved, env);
    expect(env.ANTHROPIC_BASE_URL).toBe("http://127.0.0.1:8787");
    expect(env.ANTHROPIC_UPSTREAM_BASE_URL).toBe("https://ai-gateway.vercel.sh");
  });

  it("rejects insecure custom endpoints", async () => {
    await expect(
      resolveModelRoute(
        {
          mode: "custom",
          provider: "x",
          apiKeyEnv: "X_KEY",
          baseUrl: "http://provider.example",
          credentialHeader: { name: "Authorization", scheme: "bearer" },
        },
        { agentType: "pi", env: { X_KEY: "secret" } },
      ),
    ).rejects.toThrow(/https/);
  });
});

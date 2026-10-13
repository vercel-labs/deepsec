import { describe, expect, it } from "vitest";
import { modelRouteFromCli } from "../setup/options.js";

describe("modelRouteFromCli", () => {
  it("defaults to the Vercel gateway", () => {
    expect(modelRouteFromCli({})).toEqual({ mode: "gateway", provider: "vercel" });
  });

  it("supports local subscriptions with no credential wiring", () => {
    expect(modelRouteFromCli({ modelAuth: "local" })).toEqual({ mode: "local", provider: "local" });
  });

  it("supports a direct user-owned key", () => {
    expect(
      modelRouteFromCli({
        modelAuth: "direct",
        agent: "codex",
        aiApiKeyEnv: "MY_OPENAI_KEY",
      }),
    ).toEqual({
      mode: "direct",
      provider: "openai",
      apiKeyEnv: "MY_OPENAI_KEY",
      baseUrl: undefined,
    });
  });

  it("requires complete custom credential routing", () => {
    expect(() => modelRouteFromCli({ modelAuth: "custom", aiProvider: "acme" })).toThrow(
      /requires --ai-api-key-env/,
    );
    expect(
      modelRouteFromCli({
        modelAuth: "custom",
        aiProvider: "acme",
        aiApiKeyEnv: "ACME_KEY",
        aiBaseUrl: "https://models.example.test/v1",
        aiCredentialHeader: "x-api-key:raw",
      }),
    ).toEqual({
      mode: "custom",
      provider: "acme",
      apiKeyEnv: "ACME_KEY",
      baseUrl: "https://models.example.test/v1",
      credentialHeader: { name: "x-api-key", scheme: "raw" },
    });
  });

  it("defaults authorization to bearer and other custom headers to raw", () => {
    const base = {
      modelAuth: "custom" as const,
      aiProvider: "acme",
      aiApiKeyEnv: "ACME_KEY",
      aiBaseUrl: "https://models.example.test/v1",
    };
    expect(
      modelRouteFromCli({ ...base, aiCredentialHeader: "authorization" }).credentialHeader,
    ).toEqual({ name: "authorization", scheme: "bearer" });
    expect(
      modelRouteFromCli({ ...base, aiCredentialHeader: "x-api-key" }).credentialHeader,
    ).toEqual({ name: "x-api-key", scheme: "raw" });
  });
});

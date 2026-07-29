import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { ModelRegistry, ModelRuntime } from "@earendil-works/pi-coding-agent";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  configureProviderOverrides,
  createPiReadOnlyToolDefinitions,
  registerFireworksKimiK3ModelIfNeeded,
  resolvePiModelWithDynamicGateway,
} from "../agents/pi-sdk.js";

/**
 * Registry backed by a fresh ModelRuntime with no persisted auth and no
 * models.json — only pi's built-in provider catalogs. Replaces the
 * pre-0.81 `ModelRegistry.inMemory(AuthStorage.inMemory())`.
 */
async function freshRegistry(): Promise<ModelRegistry> {
  const tmp = mkdtempSync(path.join(tmpdir(), "deepsec-pi-auth-"));
  const runtime = await ModelRuntime.create({
    authPath: path.join(tmp, "auth.json"),
    modelsPath: null,
  });
  return new ModelRegistry(runtime);
}

describe("Pi read-only tools", () => {
  let root: string;
  let outside: string;

  beforeEach(() => {
    root = mkdtempSync(path.join(tmpdir(), "deepsec-pi-root-"));
    outside = path.join(mkdtempSync(path.join(tmpdir(), "deepsec-pi-outside-")), "secret.txt");
    writeFileSync(path.join(root, "inside.ts"), "export const ok = true;\n");
    writeFileSync(outside, "do not read me\n");
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
    rmSync(path.dirname(outside), { recursive: true, force: true });
  });

  function tool(name: string) {
    const found = createPiReadOnlyToolDefinitions(root).find((t) => t.name === name);
    if (!found) throw new Error(`missing tool ${name}`);
    return found as any;
  }

  it("allows reads inside the project root", async () => {
    const result = await tool("read").execute("read-1", { path: "inside.ts" });
    expect(result.content[0].text).toContain("export const ok");
  });

  it("rejects reads outside the project root", async () => {
    await expect(tool("read").execute("read-1", { path: outside })).rejects.toThrow(
      /Path escapes project root/,
    );
  });

  it("implements find without relying on external fd downloads", async () => {
    const result = await tool("find").execute("find-1", { pattern: "*.ts" });
    expect(result.content[0].text).toContain("inside.ts");
  });
});

describe("Pi model resolution", () => {
  const KEYS = [
    "AI_GATEWAY_API_KEY",
    "VERCEL_OIDC_TOKEN",
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_BASE_URL",
    "FIREWORKS_API_KEY",
  ] as const;
  const originalEnv = Object.fromEntries(KEYS.map((key) => [key, process.env[key]]));
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    for (const key of KEYS) {
      const value = originalEnv[key];
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    globalThis.fetch = originalFetch;
  });

  it("resolves catalog gateway models via the anthropic-messages gateway api", async () => {
    // Gemini 3.x regression guard: the gateway provider must speak
    // anthropic-messages (which round-trips thinking signatures), not
    // openai-completions (which drops Gemini thought signatures and
    // 400s on every replayed tool call).
    delete process.env.AI_GATEWAY_API_KEY;
    process.env.VERCEL_OIDC_TOKEN = "oidc_test";
    process.env.OPENAI_BASE_URL = "https://ai-gateway.vercel.sh/v1";

    const registry = await freshRegistry();
    const model = await resolvePiModelWithDynamicGateway(registry, "google/gemini-3.6-flash", {});

    expect(model.provider).toBe("vercel-ai-gateway");
    expect(model.id).toBe("google/gemini-3.6-flash");
    expect(model.api).toBe("anthropic-messages");
  });

  it("registers missing Vercel AI Gateway model ids without fetching the catalog", async () => {
    delete process.env.AI_GATEWAY_API_KEY;
    process.env.VERCEL_OIDC_TOKEN = "oidc_test";
    process.env.OPENAI_API_KEY = "oidc_test";
    process.env.OPENAI_BASE_URL = "https://ai-gateway.vercel.sh/v1";
    let called = false;
    globalThis.fetch = async () => {
      called = true;
      return new Response(JSON.stringify({ data: [] }), { status: 200 });
    };

    const registry = await freshRegistry();
    // An id absent from pi's shipped gateway catalog exercises the
    // dynamic pass-through registration.
    const model = await resolvePiModelWithDynamicGateway(registry, "acme/nonexistent-model-1", {});

    expect(model.provider).toBe("vercel-ai-gateway");
    expect(model.id).toBe("acme/nonexistent-model-1");
    expect(model.name).toBe("acme/nonexistent-model-1");
    expect(model.api).toBe("anthropic-messages");
    expect(model.reasoning).toBe(true);
    expect(model.input).toEqual(["text", "image"]);
    expect(model.contextWindow).toBe(128000);
    expect(model.maxTokens).toBe(32000);
    expect(model.cost.input).toBe(0);
    expect(called).toBe(false);
  });

  it("prefers the direct provider over the gateway catalog for explicit --ai-provider overrides", async () => {
    // Since pi 0.81 the gateway catalog ships populated, so
    // `vercel-ai-gateway/xai/grok-4.5` exists out of the box. An explicit
    // custom provider override must still route to the direct provider,
    // not get shadowed by the gateway entry.
    process.env.AI_GATEWAY_API_KEY = "vck_test";
    process.env.OPENAI_BASE_URL = "https://ai-gateway.vercel.sh/v1";
    let called = false;
    globalThis.fetch = async () => {
      called = true;
      return new Response(JSON.stringify({ data: [] }), { status: 200 });
    };

    const registry = await freshRegistry();
    const model = await resolvePiModelWithDynamicGateway(registry, "xai/grok-4.5", {
      aiProvider: "xai",
      aiApiKeyEnv: "XAI_API_KEY",
    });
    expect(model.provider).toBe("xai");
    expect(model.id).toBe("grok-4.5");
    expect(called).toBe(false);
  });

  it("does not register pass-through Gateway models for explicit custom provider overrides", async () => {
    process.env.AI_GATEWAY_API_KEY = "vck_test";
    process.env.OPENAI_BASE_URL = "https://ai-gateway.vercel.sh/v1";
    let called = false;
    globalThis.fetch = async () => {
      called = true;
      return new Response(JSON.stringify({ data: [] }), { status: 200 });
    };

    const registry = await freshRegistry();
    await expect(
      resolvePiModelWithDynamicGateway(registry, "acme/nonexistent-model-1", {
        aiProvider: "acme",
      }),
    ).rejects.toThrow(/Pi model not found: acme\/nonexistent-model-1/);
    expect(called).toBe(false);
  });

  it("registers the Fireworks Kimi K3 preset offline without replacing the catalog", async () => {
    for (const key of KEYS) delete process.env[key];
    let called = false;
    globalThis.fetch = async () => {
      called = true;
      return new Response(JSON.stringify({ data: [] }), { status: 200 });
    };

    const registry = await freshRegistry();
    const existingFireworksModel = registry.find("fireworks", "accounts/fireworks/models/glm-5p2");
    expect(existingFireworksModel).toBeDefined();

    const config = {
      model: "fireworks/accounts/fireworks/models/kimi-k3",
      aiProvider: "fireworks",
      aiBaseUrl: "https://api.fireworks.ai/inference/v1",
      aiApiKeyEnv: "FIREWORKS_API_KEY",
    };
    registerFireworksKimiK3ModelIfNeeded(
      registry,
      "fireworks/accounts/fireworks/models/kimi-k3",
      config,
    );

    const model = await resolvePiModelWithDynamicGateway(
      registry,
      "fireworks/accounts/fireworks/models/kimi-k3",
      config,
    );
    expect(model.provider).toBe("fireworks");
    expect(model.id).toBe("accounts/fireworks/models/kimi-k3");
    expect(model.name).toBe("Kimi K3");
    expect(model.api).toBe("openai-completions");
    expect(model.reasoning).toBe(true);
    expect(model.input).toEqual(["text", "image"]);
    expect(model.cost).toEqual({
      input: 3,
      output: 15,
      cacheRead: 0.3,
      cacheWrite: 0,
    });
    expect(model.contextWindow).toBe(1_048_576);
    expect(model.maxTokens).toBe(131_072);
    expect(registry.find("fireworks", "accounts/fireworks/models/glm-5p2")).toBeDefined();
    expect(called).toBe(false);
  });

  it("registers the Fireworks Kimi K3 preset idempotently", async () => {
    const registry = await freshRegistry();
    const requested = "fireworks/accounts/fireworks/models/kimi-k3";
    const config = {
      model: requested,
      aiProvider: "fireworks",
      aiBaseUrl: "https://api.fireworks.ai/inference/v1",
    };

    registerFireworksKimiK3ModelIfNeeded(registry, requested, config);
    registerFireworksKimiK3ModelIfNeeded(registry, requested, config);

    expect(
      registry
        .getAll()
        .filter(
          (model) =>
            model.provider === "fireworks" && model.id === "accounts/fireworks/models/kimi-k3",
        ),
    ).toHaveLength(1);
  });

  it("preserves an existing Fireworks Kimi K3 model entry", async () => {
    const registry = await freshRegistry();
    registry.registerProvider("fireworks", {
      baseUrl: "https://user-fireworks.example.test/v1",
      api: "openai-completions",
      models: [
        {
          id: "accounts/fireworks/models/kimi-k3",
          name: "User-configured Kimi K3",
          api: "openai-completions",
          reasoning: true,
          input: ["text"],
          cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
          contextWindow: 196_608,
          maxTokens: 32_768,
        },
      ],
    });

    registerFireworksKimiK3ModelIfNeeded(registry, "fireworks/accounts/fireworks/models/kimi-k3", {
      model: "fireworks/accounts/fireworks/models/kimi-k3",
      aiProvider: "fireworks",
      aiBaseUrl: "https://api.fireworks.ai/inference/v1",
      aiBaseUrlFromPreset: true,
    });

    const model = registry.find("fireworks", "accounts/fireworks/models/kimi-k3");
    expect(model?.name).toBe("User-configured Kimi K3");
    expect(model?.contextWindow).toBe(196_608);
    expect(registry.getRegisteredProviderConfig("fireworks")?.baseUrl).toBe(
      "https://user-fireworks.example.test/v1",
    );
  });

  it("preserves a user Fireworks endpoint when the base URL came from the preset", async () => {
    const registry = await freshRegistry();
    registry.registerProvider("fireworks", {
      baseUrl: "https://user-fireworks.example.test/v1",
      api: "openai-completions",
      models: [
        {
          id: "accounts/fireworks/models/kimi-k3",
          name: "User-configured Kimi K3",
          api: "openai-completions",
          reasoning: true,
          input: ["text"],
          cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
          contextWindow: 196_608,
          maxTokens: 32_768,
        },
      ],
    });
    const config = {
      model: "fireworks/accounts/fireworks/models/kimi-k3",
      aiProvider: "fireworks",
      aiBaseUrl: "https://api.fireworks.ai/inference/v1",
      aiBaseUrlFromPreset: true,
    };

    configureProviderOverrides(registry, config);
    registerFireworksKimiK3ModelIfNeeded(
      registry,
      "fireworks/accounts/fireworks/models/kimi-k3",
      config,
    );

    expect(registry.getRegisteredProviderConfig("fireworks")?.baseUrl).toBe(
      "https://user-fireworks.example.test/v1",
    );
  });

  it("applies an explicit Fireworks base URL to an existing Kimi K3 entry", async () => {
    const registry = await freshRegistry();
    registry.registerProvider("fireworks", {
      baseUrl: "https://user-fireworks.example.test/v1",
      api: "openai-completions",
      models: [
        {
          id: "accounts/fireworks/models/kimi-k3",
          name: "User-configured Kimi K3",
          api: "openai-completions",
          reasoning: true,
          input: ["text"],
          cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
          contextWindow: 196_608,
          maxTokens: 32_768,
        },
      ],
    });

    configureProviderOverrides(registry, {
      model: "fireworks/accounts/fireworks/models/kimi-k3",
      aiProvider: "fireworks",
      aiBaseUrl: "https://explicit-fireworks.example.test/v1",
    });

    expect(registry.getRegisteredProviderConfig("fireworks")?.baseUrl).toBe(
      "https://explicit-fireworks.example.test/v1",
    );
  });

  it("keeps explicit Fireworks base URL and headers on the preset", async () => {
    const registry = await freshRegistry();
    registerFireworksKimiK3ModelIfNeeded(registry, "fireworks/accounts/fireworks/models/kimi-k3", {
      model: "fireworks/accounts/fireworks/models/kimi-k3",
      aiProvider: "fireworks",
      aiBaseUrl: "https://fireworks.example.test/v1",
      aiHeaders: { "x-fireworks-account": "test" },
    });

    expect(registry.getRegisteredProviderConfig("fireworks")).toMatchObject({
      baseUrl: "https://fireworks.example.test/v1",
      headers: { "x-fireworks-account": "test" },
    });
  });

  it("does not register Kimi K3 for a conflicting provider override", async () => {
    const registry = await freshRegistry();
    registerFireworksKimiK3ModelIfNeeded(registry, "fireworks/accounts/fireworks/models/kimi-k3", {
      model: "fireworks/accounts/fireworks/models/kimi-k3",
      aiProvider: "custom",
    });

    expect(registry.find("fireworks", "accounts/fireworks/models/kimi-k3")).toBeUndefined();
  });
});

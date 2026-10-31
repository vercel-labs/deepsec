import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { ModelRegistry, ModelRuntime } from "@earendil-works/pi-coding-agent";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  configureProviderOverrides,
  createPiReadOnlyToolDefinitions,
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
    "ACME_MODEL_KEY",
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

  it("registers App Attribution headers on the gateway provider", async () => {
    const registry = await freshRegistry();
    configureProviderOverrides(registry, {});
    const config = registry.getRegisteredProviderConfig("vercel-ai-gateway");
    expect(config?.headers).toMatchObject({
      "http-referer": "https://deepsec.sh",
    });
    expect(config?.headers?.["x-title"]).toMatch(/^deepsec/);
    // Header-only extension registration must not clobber the builtin
    // catalog — gateway models keep resolving.
    process.env.AI_GATEWAY_API_KEY = "vck_test";
    const model = await resolvePiModelWithDynamicGateway(registry, "google/gemini-3.6-flash", {});
    expect(model.provider).toBe("vercel-ai-gateway");
  });

  it("keeps attribution headers when the pass-through registration re-registers the provider", async () => {
    process.env.AI_GATEWAY_API_KEY = "vck_test";
    process.env.OPENAI_BASE_URL = "https://ai-gateway.vercel.sh/v1";
    globalThis.fetch = async () => new Response(JSON.stringify({ data: [] }), { status: 200 });

    const registry = await freshRegistry();
    configureProviderOverrides(registry, {});
    await resolvePiModelWithDynamicGateway(registry, "acme/nonexistent-model-1", {});
    const config = registry.getRegisteredProviderConfig("vercel-ai-gateway");
    expect(config?.headers?.["http-referer"]).toBe("https://deepsec.sh");
  });

  it("configures a persisted custom provider base URL and credential header", async () => {
    process.env.ACME_MODEL_KEY = "secret";
    const registry = await freshRegistry();
    configureProviderOverrides(registry, {
      aiProvider: "acme",
      aiBaseUrl: "https://models.acme.test/v1",
      aiApiKeyEnv: "ACME_MODEL_KEY",
      aiCredentialHeader: { name: "x-api-key", scheme: "raw" },
    });
    expect(registry.getRegisteredProviderConfig("acme")).toMatchObject({
      baseUrl: "https://models.acme.test/v1",
      headers: { "x-api-key": "secret" },
    });
  });
});

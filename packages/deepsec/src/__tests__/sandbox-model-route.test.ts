import { defineConfig, setLoadedConfig } from "@deepsec/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ResolvedModelRoute } from "../auth/model-route.js";
import { sandboxCommand } from "../commands/sandbox-process.js";
import { resolveRunAgentConfig } from "../run-route.js";
import { extractFlag, hasFlag } from "../sandbox/args.js";
import { extractSandboxModelRouteFlags, resolveSandboxModelRoute } from "../sandbox/route.js";
import {
  buildSandboxEnv,
  buildWorkerNetworkPolicy,
  resolveBrokeredCredentials,
} from "../sandbox/setup.js";

// `sandbox process/revalidate --model-auth` must be resolved AND brokered on
// the orchestrator host, exactly like the saved route it overrides. Workers
// have no machine-wide login and no host credential; they only see the
// placeholder env + firewall transform spawnFromSnapshot installs.
const PLACEHOLDER = "deepsec-sandbox-brokered-credential";

const MANAGED_KEYS = [
  "AI_GATEWAY_API_KEY",
  "ANTHROPIC_API_KEY",
  "ANTHROPIC_AUTH_TOKEN",
  "ANTHROPIC_BASE_URL",
  "ANTHROPIC_UPSTREAM_BASE_URL",
  "ACME_MODEL_KEY",
  "DEEPSEC_INSIDE_SANDBOX",
  "DEEPSEC_PI_AI_BASE_URL",
  "OPENAI_API_KEY",
  "OPENAI_BASE_URL",
  "VERCEL_OIDC_TOKEN",
  "VERCEL_PROJECT_ID",
  "VERCEL_TEAM_ID",
  "VERCEL_TOKEN",
] as const;

let saved: Record<string, string | undefined> = {};

beforeEach(() => {
  saved = {};
  for (const key of MANAGED_KEYS) {
    saved[key] = process.env[key];
    delete process.env[key];
  }
  setLoadedConfig(defineConfig({ projects: [] }));
});

afterEach(() => {
  for (const key of MANAGED_KEYS) {
    if (saved[key] === undefined) delete process.env[key];
    else process.env[key] = saved[key];
  }
  setLoadedConfig(defineConfig({ projects: [] }));
});

/** The env spawnFromSnapshot hands to Sandbox.create for a resolved route. */
function workerSpawn(
  agentType: string,
  resolved: ResolvedModelRoute,
  options: { aiApiKeyEnv?: string; aiBaseUrl?: string } = {},
) {
  const credentials = resolveBrokeredCredentials(agentType, {
    ...options,
    brokeredModelCredential: resolved.broker,
  });
  const env = buildSandboxEnv(agentType, credentials, options);
  return { credentials, env };
}

/** Replace this process env with the worker env a sandboxed CLI would see. */
function becomeWorker(env: Record<string, string>): void {
  for (const key of MANAGED_KEYS) delete process.env[key];
  for (const [key, value] of Object.entries(env)) process.env[key] = value;
}

describe("extractFlag / hasFlag (sandbox passthrough)", () => {
  it("reads both --flag value and --flag=value spellings", () => {
    expect(extractFlag(["--limit", "5"], "--limit")).toBe("5");
    expect(extractFlag(["--limit=5"], "--limit")).toBe("5");
    expect(extractFlag(["--limit", "--force"], "--limit")).toBeUndefined();
    expect(hasFlag(["--force"], "--force")).toBe(true);
  });
});

describe("extractSandboxModelRouteFlags", () => {
  it("reads every one-run route flag from the passthrough args", () => {
    expect(
      extractSandboxModelRouteFlags([
        "--model-auth",
        "custom",
        "--ai-provider",
        "acme",
        "--ai-base-url",
        "https://models.acme.test/v1",
        "--ai-api-key-env",
        "ACME_MODEL_KEY",
        "--ai-credential-header",
        "x-api-key:raw",
      ]),
    ).toEqual({
      modelAuth: "custom",
      aiProvider: "acme",
      aiBaseUrl: "https://models.acme.test/v1",
      aiApiKeyEnv: "ACME_MODEL_KEY",
      aiCredentialHeader: "x-api-key:raw",
    });
  });

  it("accepts the equals spelling", () => {
    expect(extractSandboxModelRouteFlags(["--model-auth=gateway"])).toEqual({
      modelAuth: "gateway",
    });
  });

  it("returns no override when --model-auth is absent", () => {
    expect(extractSandboxModelRouteFlags(["--agent", "codex", "--limit", "5"])).toEqual({});
  });

  it("rejects a bare --model-auth instead of silently using the saved route", () => {
    expect(() => extractSandboxModelRouteFlags(["--model-auth"])).toThrow(
      /--model-auth requires a value/,
    );
    expect(() => extractSandboxModelRouteFlags(["--model-auth", "--limit", "5"])).toThrow(
      /--model-auth requires a value/,
    );
  });
});

describe("resolveSandboxModelRoute", () => {
  it("leaves the saved route alone when no override is given", async () => {
    await expect(resolveSandboxModelRoute({}, "codex")).resolves.toBeUndefined();
  });

  it("brokers --model-auth gateway so the worker can re-resolve it", async () => {
    // AI_GATEWAY_API_KEY is the one credential applyAiGatewayDefaults expands
    // into the per-SDK env the sandbox brokers from.
    process.env.AI_GATEWAY_API_KEY = "vck_host_secret";
    process.env.OPENAI_API_KEY = "vck_host_secret";
    process.env.OPENAI_BASE_URL = "https://ai-gateway.vercel.sh/v1";

    const resolved = await resolveSandboxModelRoute({ modelAuth: "gateway" }, "codex");
    expect(resolved).toBeDefined();
    expect(resolved?.broker).toMatchObject({
      host: "ai-gateway.vercel.sh",
      placeholderEnv: "AI_GATEWAY_API_KEY",
    });

    const { env, credentials } = workerSpawn("codex", resolved!);
    // The worker only ever sees placeholders ...
    expect(env.AI_GATEWAY_API_KEY).toBe(PLACEHOLDER);
    expect(env.OPENAI_API_KEY).toBe(PLACEHOLDER);
    expect(env.OPENAI_BASE_URL).toBe("https://ai-gateway.vercel.sh/v1");
    for (const value of Object.values(env)) expect(value).not.toContain("vck_host_secret");
    // ... while the firewall injects the real bearer token at the gateway host.
    const policy = JSON.stringify(buildWorkerNetworkPolicy(env, "codex", credentials));
    expect(policy).toContain("ai-gateway.vercel.sh");
    expect(policy).toContain("Bearer vck_host_secret");

    becomeWorker(env);
    const { agentConfig, explicitRoute } = await resolveRunAgentConfig({
      agentType: "codex",
      model: "gpt-5.5",
      modelAuth: "gateway",
    });
    expect(explicitRoute).toEqual({ mode: "gateway", provider: "vercel" });
    expect(agentConfig.modelAuth).toBe("gateway");
  });

  it("brokers gateway placeholders for a Claude worker too", async () => {
    process.env.AI_GATEWAY_API_KEY = "vck_host_secret";
    const resolved = await resolveSandboxModelRoute({ modelAuth: "gateway" }, "claude-agent-sdk");

    const { env } = workerSpawn("claude-agent-sdk", resolved!);
    expect(env.AI_GATEWAY_API_KEY).toBe(PLACEHOLDER);
    expect(env.ANTHROPIC_AUTH_TOKEN).toBe(PLACEHOLDER);
    expect(env.ANTHROPIC_UPSTREAM_BASE_URL).toBe("https://ai-gateway.vercel.sh");
    for (const value of Object.values(env)) expect(value).not.toContain("vck_host_secret");

    becomeWorker(env);
    await expect(
      resolveRunAgentConfig({
        agentType: "claude-agent-sdk",
        model: "claude-opus-4-8",
        modelAuth: "gateway",
      }),
    ).resolves.toMatchObject({ explicitRoute: { mode: "gateway" } });
  });

  it("documents the pre-fix worker failure: no brokered AI_GATEWAY_API_KEY", async () => {
    // Before the orchestrator resolved --model-auth it brokered only ambient
    // tokens, so a Codex worker got an OPENAI placeholder but no
    // AI_GATEWAY_API_KEY and died re-resolving the explicit gateway route.
    process.env.AI_GATEWAY_API_KEY = "vck_host_secret";
    process.env.OPENAI_API_KEY = "vck_host_secret";
    process.env.OPENAI_BASE_URL = "https://ai-gateway.vercel.sh/v1";
    const credentials = resolveBrokeredCredentials("codex");
    const env = buildSandboxEnv("codex", credentials);
    expect(env.AI_GATEWAY_API_KEY).toBeUndefined();
    expect(env.OPENAI_API_KEY).toBe(PLACEHOLDER);

    becomeWorker(env);
    await expect(
      resolveRunAgentConfig({ agentType: "codex", model: "gpt-5.5", modelAuth: "gateway" }),
    ).rejects.toThrow(/AI_GATEWAY_API_KEY/);
  });

  it("rejects gateway and direct overrides without a host credential", async () => {
    // The parent preflight fails with the route's own actionable credential
    // error, before the Vercel Sandbox preflight or any worker exists.
    await expect(resolveSandboxModelRoute({ modelAuth: "gateway" }, "codex")).rejects.toThrow(
      /AI_GATEWAY_API_KEY/,
    );
    await expect(resolveSandboxModelRoute({ modelAuth: "direct" }, "codex")).rejects.toThrow(
      /requires OPENAI_API_KEY/,
    );
  });

  it("rejects --model-auth local before provisioning anything", async () => {
    const failure = resolveSandboxModelRoute({ modelAuth: "local" }, "codex");
    await expect(failure).rejects.toThrow(
      /--model-auth local is not supported with deepsec sandbox/,
    );
    await expect(failure).rejects.toThrow(/Run process or revalidate locally/);
    await expect(failure).rejects.toThrow(/--model-auth gateway/);
  });

  it("brokers a direct route and the worker keeps the provider base URL", async () => {
    process.env.OPENAI_API_KEY = "sk-host-secret";

    const resolved = await resolveSandboxModelRoute({ modelAuth: "direct" }, "codex");
    expect(resolved?.route).toMatchObject({ mode: "direct", provider: "openai" });
    expect(resolved?.broker).toMatchObject({
      host: "api.openai.com",
      placeholderEnv: "OPENAI_API_KEY",
    });

    const { env } = workerSpawn("codex", resolved!);
    expect(env.OPENAI_API_KEY).toBe(PLACEHOLDER);
    expect(env.OPENAI_BASE_URL).toBe("https://api.openai.com/v1");
    for (const value of Object.values(env)) expect(value).not.toContain("sk-host-secret");

    becomeWorker(env);
    await expect(
      resolveRunAgentConfig({ agentType: "codex", model: "gpt-5.5", modelAuth: "direct" }),
    ).resolves.toMatchObject({ explicitRoute: { mode: "direct", provider: "openai" } });
  });

  it("brokers a custom Pi route, including the in-VM base URL", async () => {
    process.env.ACME_MODEL_KEY = "acme-host-secret";
    const flags = {
      modelAuth: "custom" as const,
      aiProvider: "acme",
      aiBaseUrl: "https://models.acme.test/v1",
      aiApiKeyEnv: "ACME_MODEL_KEY",
      aiCredentialHeader: "x-api-key:raw",
    };

    const resolved = await resolveSandboxModelRoute(flags, "pi");
    expect(resolved?.broker).toMatchObject({
      host: "models.acme.test",
      placeholderEnv: "ACME_MODEL_KEY",
      header: { name: "x-api-key", value: "acme-host-secret" },
    });

    const { env } = workerSpawn("pi", resolved!, {
      aiApiKeyEnv: "ACME_MODEL_KEY",
      aiBaseUrl: "https://models.acme.test/v1",
    });
    expect(env.ACME_MODEL_KEY).toBe(PLACEHOLDER);
    expect(env.DEEPSEC_PI_AI_BASE_URL).toBe("https://models.acme.test/v1");
    for (const value of Object.values(env)) expect(value).not.toContain("acme-host-secret");

    becomeWorker(env);
    await expect(
      resolveRunAgentConfig({ agentType: "pi", model: "acme/security-model", ...flags }),
    ).resolves.toMatchObject({ explicitRoute: { mode: "custom", provider: "acme" } });
  });

  it("keeps custom routes Pi-only in the sandbox parent preflight", async () => {
    process.env.ACME_MODEL_KEY = "acme-host-secret";
    await expect(
      resolveSandboxModelRoute(
        {
          modelAuth: "custom",
          aiProvider: "acme",
          aiBaseUrl: "https://models.acme.test/v1",
          aiApiKeyEnv: "ACME_MODEL_KEY",
          aiCredentialHeader: "x-api-key:raw",
        },
        "codex",
      ),
    ).rejects.toThrow(/Custom model routes require --agent pi/);
  });
});

describe("sandbox process --model-auth at the command boundary", () => {
  beforeEach(() => {
    setLoadedConfig(defineConfig({ projects: [{ id: "app", root: "/tmp/app" }] }));
  });

  it("resolves and brokers gateway before the Vercel Sandbox preflight", async () => {
    process.env.AI_GATEWAY_API_KEY = "vck_host_secret";
    // Route resolution + brokering happen first; the missing Sandbox
    // credentials then fail the host preflight before any worker starts.
    await expect(
      sandboxCommand("process", { projectId: "app", args: ["--model-auth", "gateway"] }),
    ).rejects.toThrow(/Missing Vercel Sandbox credentials/);
  });

  it("lets --model-auth gateway override a saved local route in the parent", async () => {
    // The reported case: a saved local route must not stop the one-run gateway
    // escape hatch from being resolved and brokered on the orchestrator.
    setLoadedConfig(
      defineConfig({
        projects: [{ id: "app", root: "/tmp/app" }],
        ai: { mode: "local", provider: "local" },
      }),
    );
    process.env.AI_GATEWAY_API_KEY = "vck_host_secret";
    await expect(
      sandboxCommand("process", { projectId: "app", args: ["--model-auth", "gateway"] }),
    ).rejects.toThrow(/Missing Vercel Sandbox credentials/);
  });

  it("rejects --model-auth local in the parent, not in the worker", async () => {
    await expect(
      sandboxCommand("process", { projectId: "app", args: ["--model-auth", "local"] }),
    ).rejects.toThrow(/--model-auth local is not supported with deepsec sandbox/);
  });

  it("rejects an incompatible custom route in the parent", async () => {
    process.env.ACME_MODEL_KEY = "acme-host-secret";
    await expect(
      sandboxCommand("process", {
        projectId: "app",
        args: [
          "--agent",
          "codex",
          "--model-auth",
          "custom",
          "--ai-provider",
          "acme",
          "--ai-base-url",
          "https://models.acme.test/v1",
          "--ai-api-key-env",
          "ACME_MODEL_KEY",
          "--ai-credential-header",
          "x-api-key:raw",
        ],
      }),
    ).rejects.toThrow(/Custom model routes require --agent pi/);
  });

  it("rejects a bare --model-auth in the parent", async () => {
    await expect(
      sandboxCommand("process", { projectId: "app", args: ["--model-auth"] }),
    ).rejects.toThrow(/--model-auth requires a value/);
  });
});

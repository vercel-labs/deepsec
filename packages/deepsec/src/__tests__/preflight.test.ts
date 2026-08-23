import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setLoadedConfig } from "@deepsec/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Stub @vercel/oidc so the preflight suite is hermetic: the real
// implementation decodes VERCEL_OIDC_TOKEN as a JWT and, on failure,
// falls back to reading `.vercel/project.json` and hitting Vercel. That
// would leak the dev's local project state into the test and 401 on CI
// (and the synthetic strings we use below aren't valid JWTs). Treating
// the env var as the source of truth matches what applyAiGatewayDefaults
// relies on: a token populated by `vercel env pull`.
vi.mock("@vercel/oidc", () => ({
  getVercelOidcToken: async () => {
    const token = process.env.VERCEL_OIDC_TOKEN;
    if (!token) throw new Error("no VERCEL_OIDC_TOKEN");
    return token;
  },
}));

import {
  applyAiGatewayDefaults,
  applyConfiguredModelRoute,
  assertAgentCredential,
  assertSandboxCredential,
  reconcileAiGatewayDefaultsForRoute,
} from "../preflight.js";

describe("applyConfiguredModelRoute", () => {
  afterEach(() => setLoadedConfig({ projects: [] }));

  it("rehydrates a persisted direct route from its named variable", async () => {
    setLoadedConfig({
      projects: [],
      ai: { mode: "direct", provider: "openai", apiKeyEnv: "MY_OPENAI_KEY" },
    });
    const env = { MY_OPENAI_KEY: "secret" };
    const resolved = await applyConfiguredModelRoute("codex", env);
    expect(resolved?.credentialEnv).toBe("MY_OPENAI_KEY");
    expect(env).toMatchObject({
      OPENAI_API_KEY: "secret",
      OPENAI_BASE_URL: "https://api.openai.com/v1",
    });
  });

  it("leaves a credential-free scaffold gateway route to subscription auth", async () => {
    setLoadedConfig({ projects: [], ai: { mode: "gateway", provider: "vercel" } });
    const env = {};
    await expect(applyConfiguredModelRoute("codex", env)).resolves.toBeUndefined();
    expect(env).toEqual({});
  });

  it("leaves a local-subscription route entirely to machine-wide agent logins", async () => {
    setLoadedConfig({ projects: [], ai: { mode: "local", provider: "local" } });
    const env = {};
    await expect(applyConfiguredModelRoute("codex", env)).resolves.toBeUndefined();
    await expect(applyConfiguredModelRoute("claude-agent-sdk", env)).resolves.toBeUndefined();
    expect(env).toEqual({});
  });

  it("ignores a persisted route that is incompatible with the requested harness", async () => {
    setLoadedConfig({
      projects: [],
      ai: { mode: "direct", provider: "openai", apiKeyEnv: "MY_OPENAI_KEY" },
    });
    const env = { MY_OPENAI_KEY: "secret" };
    await expect(applyConfiguredModelRoute("claude-agent-sdk", env)).resolves.toBeUndefined();
    expect(env).toEqual({ MY_OPENAI_KEY: "secret" });
  });
});

describe("assertAgentCredential", () => {
  let saved: Record<string, string | undefined>;
  let emptyClaudeHome: string;
  let emptyCodexHome: string;
  let emptyPathDir: string;
  beforeEach(() => {
    saved = {
      ANTHROPIC_AUTH_TOKEN: process.env.ANTHROPIC_AUTH_TOKEN,
      OPENAI_API_KEY: process.env.OPENAI_API_KEY,
      ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY,
      AI_GATEWAY_API_KEY: process.env.AI_GATEWAY_API_KEY,
      MARTIAN_API_KEY: process.env.MARTIAN_API_KEY,
      CLAUDE_HOME: process.env.CLAUDE_HOME,
      CODEX_HOME: process.env.CODEX_HOME,
      PI_CODING_AGENT_DIR: process.env.PI_CODING_AGENT_DIR,
      PATH: process.env.PATH,
    };
    delete process.env.ANTHROPIC_AUTH_TOKEN;
    delete process.env.OPENAI_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;
    delete process.env.AI_GATEWAY_API_KEY;
    delete process.env.MARTIAN_API_KEY;
    // Point CLAUDE_HOME / CODEX_HOME and PATH at empty tmp dirs so the
    // suite is hermetic — the dev running tests may have a real
    // ~/.codex/auth.json or `claude` on $PATH, which would cause
    // "no token" tests to incorrectly pass.
    emptyClaudeHome = mkdtempSync(join(tmpdir(), "deepsec-claude-home-"));
    emptyCodexHome = mkdtempSync(join(tmpdir(), "deepsec-codex-home-"));
    emptyPathDir = mkdtempSync(join(tmpdir(), "deepsec-empty-path-"));
    process.env.CLAUDE_HOME = emptyClaudeHome;
    process.env.CODEX_HOME = emptyCodexHome;
    process.env.PI_CODING_AGENT_DIR = join(emptyCodexHome, "pi-agent");
    mkdirSync(process.env.PI_CODING_AGENT_DIR, { recursive: true });
    process.env.PATH = emptyPathDir;
  });
  afterEach(() => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    rmSync(emptyClaudeHome, { recursive: true, force: true });
    rmSync(emptyCodexHome, { recursive: true, force: true });
    rmSync(emptyPathDir, { recursive: true, force: true });
    setLoadedConfig({ projects: [] });
  });

  it("passes for claude-agent-sdk when ANTHROPIC_AUTH_TOKEN is set", () => {
    process.env.ANTHROPIC_AUTH_TOKEN = "x";
    expect(() => assertAgentCredential("claude-agent-sdk")).not.toThrow();
  });

  it("passes for direct Anthropic when ANTHROPIC_API_KEY is set", () => {
    process.env.ANTHROPIC_API_KEY = "x";
    expect(() => assertAgentCredential("claude-agent-sdk")).not.toThrow();
  });

  it("throws actionable message for claude-agent-sdk when no token and no claude CLI", () => {
    expect(() => assertAgentCredential("claude-agent-sdk")).toThrow(/--agent claude/);
    expect(() => assertAgentCredential("claude-agent-sdk")).toThrow(/ANTHROPIC_AUTH_TOKEN/);
    expect(() => assertAgentCredential("claude-agent-sdk")).toThrow(/AI_GATEWAY_API_KEY/);
    expect(() => assertAgentCredential("claude-agent-sdk")).toThrow(
      /https:\/\/github\.com\/vercel-labs\/deepsec\/blob\/main\/docs\/vercel-setup\.md/,
    );
  });

  it("passes for claude-agent-sdk when `claude` is on PATH (subscription mode)", () => {
    writeFileSync(join(emptyPathDir, "claude"), "#!/bin/sh\n", { mode: 0o755 });
    expect(() => assertAgentCredential("claude-agent-sdk")).not.toThrow();
  });

  it("ignores claude subscription auth in sandbox mode", () => {
    writeFileSync(join(emptyPathDir, "claude"), "#!/bin/sh\n", { mode: 0o755 });
    expect(() => assertAgentCredential("claude-agent-sdk", { inSandbox: true })).toThrow(
      /AI_GATEWAY_API_KEY/,
    );
  });

  it("passes for codex when OPENAI_API_KEY is set", () => {
    process.env.OPENAI_API_KEY = "x";
    expect(() => assertAgentCredential("codex")).not.toThrow();
  });

  it("passes for codex when only ANTHROPIC token is set (gateway fallback)", () => {
    process.env.ANTHROPIC_AUTH_TOKEN = "x";
    expect(() => assertAgentCredential("codex")).not.toThrow();
  });

  it("passes for codex when ~/.codex/auth.json exists (subscription mode)", () => {
    writeFileSync(join(emptyCodexHome, "auth.json"), "{}");
    expect(() => assertAgentCredential("codex")).not.toThrow();
  });

  it("ignores codex subscription auth in sandbox mode", () => {
    writeFileSync(join(emptyCodexHome, "auth.json"), "{}");
    // With auth.json present, non-sandbox passes — sandbox still throws.
    expect(() => assertAgentCredential("codex")).not.toThrow();
    expect(() => assertAgentCredential("codex", { inSandbox: true })).toThrow(/OPENAI_API_KEY/);
  });

  it("does not let claude subscription unlock codex", () => {
    writeFileSync(join(emptyPathDir, "claude"), "#!/bin/sh\n", { mode: 0o755 });
    // No codex auth.json → still throws.
    expect(() => assertAgentCredential("codex")).toThrow(/OPENAI_API_KEY/);
    expect(() => assertAgentCredential("codex")).toThrow(/AI_GATEWAY_API_KEY/);
  });

  it("skips the credential check for custom plugin agents", () => {
    // Tests use this so a stub agent registered via plugins[] doesn't
    // require fake ANTHROPIC_AUTH_TOKEN env vars.
    expect(() => assertAgentCredential("stub")).not.toThrow();
    expect(() => assertAgentCredential("anything-else")).not.toThrow();
  });

  it("skips all env-var checks when the configured route is local subscriptions", () => {
    setLoadedConfig({ projects: [], ai: { mode: "local", provider: "local" } });
    // Nothing set anywhere — no env vars, no CLI on PATH, no auth.json.
    expect(() => assertAgentCredential("claude-agent-sdk")).not.toThrow();
    expect(() => assertAgentCredential("codex")).not.toThrow();
    expect(() => assertAgentCredential("pi")).not.toThrow();
  });

  it("still requires a brokered token in sandbox mode despite a local route", () => {
    setLoadedConfig({ projects: [], ai: { mode: "local", provider: "local" } });
    expect(() => assertAgentCredential("codex", { inSandbox: true })).toThrow(/AI_GATEWAY_API_KEY/);
    // An ambient gateway key still unlocks sandbox runs.
    process.env.AI_GATEWAY_API_KEY = "vck_gateway";
    process.env.OPENAI_API_KEY = "vck_gateway";
    expect(() => assertAgentCredential("codex", { inSandbox: true })).not.toThrow();
  });

  it("passes for pi when AI_GATEWAY_API_KEY is set", () => {
    process.env.AI_GATEWAY_API_KEY = "vck_gateway";
    expect(() => assertAgentCredential("pi")).not.toThrow();
  });

  it("passes for pi when a custom --ai-api-key-env is set", () => {
    process.env.MARTIAN_API_KEY = "martian-key";
    expect(() => assertAgentCredential("pi", { aiApiKeyEnv: "MARTIAN_API_KEY" })).not.toThrow();
  });

  it("passes for pi when local Pi auth exists outside sandbox", () => {
    const piHome = process.env.PI_CODING_AGENT_DIR!;
    writeFileSync(join(piHome, "auth.json"), "{}");
    expect(() => assertAgentCredential("pi")).not.toThrow();
  });

  it("ignores local Pi auth in sandbox mode", () => {
    const piHome = process.env.PI_CODING_AGENT_DIR!;
    writeFileSync(join(piHome, "auth.json"), "{}");
    expect(() => assertAgentCredential("pi", { inSandbox: true })).toThrow(/AI_GATEWAY_API_KEY/);
  });
});

describe("assertSandboxCredential", () => {
  let saved: Record<string, string | undefined>;
  beforeEach(() => {
    saved = {
      VERCEL_OIDC_TOKEN: process.env.VERCEL_OIDC_TOKEN,
      VERCEL_TOKEN: process.env.VERCEL_TOKEN,
      VERCEL_TEAM_ID: process.env.VERCEL_TEAM_ID,
      VERCEL_PROJECT_ID: process.env.VERCEL_PROJECT_ID,
    };
    for (const k of Object.keys(saved)) delete process.env[k];
  });
  afterEach(() => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });

  it("passes when OIDC token is set", () => {
    process.env.VERCEL_OIDC_TOKEN = "x";
    expect(() => assertSandboxCredential()).not.toThrow();
  });

  it("passes when access-token triple is set", () => {
    process.env.VERCEL_TOKEN = "x";
    process.env.VERCEL_TEAM_ID = "team_x";
    process.env.VERCEL_PROJECT_ID = "prj_x";
    expect(() => assertSandboxCredential()).not.toThrow();
  });

  it("throws actionable message when nothing is set", () => {
    expect(() => assertSandboxCredential()).toThrow(/vercel link/);
    expect(() => assertSandboxCredential()).toThrow(/VERCEL_OIDC_TOKEN/);
    expect(() => assertSandboxCredential()).toThrow(
      /https:\/\/github\.com\/vercel-labs\/deepsec\/blob\/main\/docs\/vercel-setup\.md/,
    );
  });

  it("names every missing access-token piece", () => {
    process.env.VERCEL_TOKEN = "x";
    expect(() => assertSandboxCredential()).toThrow(/VERCEL_TEAM_ID, VERCEL_PROJECT_ID/);
  });
});

describe("applyAiGatewayDefaults", () => {
  let saved: Record<string, string | undefined>;
  beforeEach(() => {
    saved = {
      AI_GATEWAY_API_KEY: process.env.AI_GATEWAY_API_KEY,
      VERCEL_OIDC_TOKEN: process.env.VERCEL_OIDC_TOKEN,
      ANTHROPIC_AUTH_TOKEN: process.env.ANTHROPIC_AUTH_TOKEN,
      OPENAI_API_KEY: process.env.OPENAI_API_KEY,
      ANTHROPIC_BASE_URL: process.env.ANTHROPIC_BASE_URL,
      OPENAI_BASE_URL: process.env.OPENAI_BASE_URL,
    };
    for (const k of Object.keys(saved)) delete process.env[k];
  });
  afterEach(() => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    setLoadedConfig({ projects: [] });
  });

  it("does nothing when AI_GATEWAY_API_KEY is unset", async () => {
    await applyAiGatewayDefaults();
    expect(process.env.ANTHROPIC_AUTH_TOKEN).toBeUndefined();
    expect(process.env.OPENAI_API_KEY).toBeUndefined();
    expect(process.env.ANTHROPIC_BASE_URL).toBeUndefined();
    expect(process.env.OPENAI_BASE_URL).toBeUndefined();
  });

  it("populates all four vars from AI_GATEWAY_API_KEY", async () => {
    process.env.AI_GATEWAY_API_KEY = "gw-key";
    await applyAiGatewayDefaults();
    expect(process.env.ANTHROPIC_AUTH_TOKEN).toBe("gw-key");
    expect(process.env.OPENAI_API_KEY).toBe("gw-key");
    expect(process.env.ANTHROPIC_BASE_URL).toBe("https://ai-gateway.vercel.sh");
    expect(process.env.OPENAI_BASE_URL).toBe("https://ai-gateway.vercel.sh/v1");
  });

  it("does not overwrite explicit ANTHROPIC_AUTH_TOKEN", async () => {
    process.env.AI_GATEWAY_API_KEY = "gw-key";
    process.env.ANTHROPIC_AUTH_TOKEN = "explicit-anthropic";
    await applyAiGatewayDefaults();
    expect(process.env.ANTHROPIC_AUTH_TOKEN).toBe("explicit-anthropic");
    expect(process.env.OPENAI_API_KEY).toBe("gw-key");
  });

  it("does not overwrite an explicit ANTHROPIC_BASE_URL pointing direct-to-provider", async () => {
    process.env.AI_GATEWAY_API_KEY = "gw-key";
    process.env.ANTHROPIC_BASE_URL = "https://api.anthropic.com";
    await applyAiGatewayDefaults();
    expect(process.env.ANTHROPIC_BASE_URL).toBe("https://api.anthropic.com");
    expect(process.env.OPENAI_BASE_URL).toBe("https://ai-gateway.vercel.sh/v1");
  });

  it("falls back to VERCEL_OIDC_TOKEN when AI_GATEWAY_API_KEY is unset", async () => {
    process.env.VERCEL_OIDC_TOKEN = "oidc-tok";
    await applyAiGatewayDefaults();
    expect(process.env.AI_GATEWAY_API_KEY).toBe("oidc-tok");
    expect(process.env.ANTHROPIC_AUTH_TOKEN).toBe("oidc-tok");
    expect(process.env.OPENAI_API_KEY).toBe("oidc-tok");
    expect(process.env.ANTHROPIC_BASE_URL).toBe("https://ai-gateway.vercel.sh");
    expect(process.env.OPENAI_BASE_URL).toBe("https://ai-gateway.vercel.sh/v1");
  });

  it("does not invoke @vercel/oidc when no VERCEL_OIDC_TOKEN is in env", async () => {
    // Guard against the library walking up from cwd looking for a parent
    // `.vercel/project.json`. Without VERCEL_OIDC_TOKEN as the explicit
    // opt-in, we leave AI_GATEWAY_API_KEY unset and fall through to the
    // claude/codex subscription path.
    let invoked = false;
    const oidcModule = await import("@vercel/oidc");
    const spy = vi.spyOn(oidcModule, "getVercelOidcToken").mockImplementation(async () => {
      invoked = true;
      return "should-not-be-used";
    });
    await applyAiGatewayDefaults();
    expect(invoked).toBe(false);
    expect(process.env.AI_GATEWAY_API_KEY).toBeUndefined();
    expect(process.env.ANTHROPIC_AUTH_TOKEN).toBeUndefined();
    expect(process.env.ANTHROPIC_BASE_URL).toBeUndefined();
    spy.mockRestore();
  });

  it("prefers an explicit AI_GATEWAY_API_KEY over VERCEL_OIDC_TOKEN", async () => {
    process.env.AI_GATEWAY_API_KEY = "gw-key";
    process.env.VERCEL_OIDC_TOKEN = "oidc-tok";
    await applyAiGatewayDefaults();
    expect(process.env.AI_GATEWAY_API_KEY).toBe("gw-key");
    expect(process.env.ANTHROPIC_AUTH_TOKEN).toBe("gw-key");
    expect(process.env.OPENAI_API_KEY).toBe("gw-key");
  });

  it("removes unchanged OIDC-derived defaults for a configured local route", async () => {
    process.env.VERCEL_OIDC_TOKEN = "oidc-tok";
    await applyAiGatewayDefaults();
    setLoadedConfig({ projects: [], ai: { mode: "local", provider: "local" } });

    await applyConfiguredModelRoute("codex");

    expect(process.env.VERCEL_OIDC_TOKEN).toBe("oidc-tok");
    expect(process.env.AI_GATEWAY_API_KEY).toBeUndefined();
    expect(process.env.ANTHROPIC_AUTH_TOKEN).toBeUndefined();
    expect(process.env.OPENAI_API_KEY).toBeUndefined();
    expect(process.env.ANTHROPIC_BASE_URL).toBeUndefined();
    expect(process.env.OPENAI_BASE_URL).toBeUndefined();
  });

  it("preserves values changed after startup while reconciling a local route", async () => {
    process.env.VERCEL_OIDC_TOKEN = "oidc-tok";
    await applyAiGatewayDefaults();
    process.env.OPENAI_API_KEY = "user-openai-key";
    process.env.ANTHROPIC_BASE_URL = "https://api.anthropic.com";

    reconcileAiGatewayDefaultsForRoute({ mode: "local", provider: "local" });

    expect(process.env.OPENAI_API_KEY).toBe("user-openai-key");
    expect(process.env.ANTHROPIC_BASE_URL).toBe("https://api.anthropic.com");
    expect(process.env.AI_GATEWAY_API_KEY).toBeUndefined();
    expect(process.env.ANTHROPIC_AUTH_TOKEN).toBeUndefined();
    expect(process.env.OPENAI_BASE_URL).toBeUndefined();
  });

  it("keeps OIDC-derived defaults for Gateway and local-route sandbox runs", async () => {
    process.env.VERCEL_OIDC_TOKEN = "oidc-tok";
    await applyAiGatewayDefaults();

    reconcileAiGatewayDefaultsForRoute({ mode: "gateway", provider: "vercel" });
    reconcileAiGatewayDefaultsForRoute({ mode: "local", provider: "local" }, { inSandbox: true });

    expect(process.env.AI_GATEWAY_API_KEY).toBe("oidc-tok");
    expect(process.env.ANTHROPIC_AUTH_TOKEN).toBe("oidc-tok");
    expect(process.env.OPENAI_API_KEY).toBe("oidc-tok");
    expect(process.env.ANTHROPIC_BASE_URL).toBe("https://ai-gateway.vercel.sh");
    expect(process.env.OPENAI_BASE_URL).toBe("https://ai-gateway.vercel.sh/v1");
  });

  it("preserves OIDC-derived credentials when a configured local route runs in a sandbox", async () => {
    process.env.VERCEL_OIDC_TOKEN = "oidc-tok";
    await applyAiGatewayDefaults();
    setLoadedConfig({ projects: [], ai: { mode: "local", provider: "local" } });

    await applyConfiguredModelRoute("codex", process.env, { inSandbox: true });

    expect(process.env.AI_GATEWAY_API_KEY).toBe("oidc-tok");
    expect(process.env.OPENAI_API_KEY).toBe("oidc-tok");
    expect(() => assertAgentCredential("codex", { inSandbox: true })).not.toThrow();
  });
});

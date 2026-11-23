import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setLoadedConfig } from "@deepsec/core";
import { resolveCodexAuth } from "@deepsec/processor";
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
  applyCommandModelRoute,
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

describe("applyCommandModelRoute", () => {
  // `process` / `revalidate --model-auth` is the per-run escape hatch from a
  // saved local-subscription route: it reuses the same route resolution as
  // init/setup, for one command only.
  it("applies an explicit gateway route for a single run", async () => {
    const env: NodeJS.ProcessEnv = { AI_GATEWAY_API_KEY: "vck_run" };
    const route = await applyCommandModelRoute(
      { mode: "gateway", provider: "vercel" },
      "codex",
      env,
    );

    expect(route).toEqual({ mode: "gateway", provider: "vercel" });
    expect(env.OPENAI_API_KEY).toBe("vck_run");
    expect(env.OPENAI_BASE_URL).toBe("https://ai-gateway.vercel.sh/v1");
  });

  it("accepts an explicit local route without a brokerable credential", async () => {
    const env: NodeJS.ProcessEnv = {};
    const route = await applyCommandModelRoute({ mode: "local", provider: "local" }, "codex", env);

    expect(route).toEqual({ mode: "local", provider: "local" });
    expect(env).toEqual({});
  });

  it("still rejects gateway routes with no credential", async () => {
    await expect(
      applyCommandModelRoute({ mode: "gateway", provider: "vercel" }, "codex", {}),
    ).rejects.toThrow(/AI_GATEWAY_API_KEY/);
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
      HOME: process.env.HOME,
      USERPROFILE: process.env.USERPROFILE,
      DEEPSEC_INSIDE_SANDBOX: process.env.DEEPSEC_INSIDE_SANDBOX,
    };
    delete process.env.ANTHROPIC_AUTH_TOKEN;
    delete process.env.OPENAI_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;
    delete process.env.AI_GATEWAY_API_KEY;
    delete process.env.MARTIAN_API_KEY;
    delete process.env.DEEPSEC_INSIDE_SANDBOX;
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
    // os.homedir() is the fallback location for a Codex login; point it at an
    // empty dir so a developer's real ~/.codex/auth.json cannot satisfy the
    // local-route checks below.
    process.env.HOME = emptyCodexHome;
    process.env.USERPROFILE = emptyCodexHome;
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

  it("leaves claude and pi local routes to their machine-wide logins", () => {
    setLoadedConfig({ projects: [], ai: { mode: "local", provider: "local" } });
    // Nothing set anywhere — no env vars, no CLI on PATH, no auth.json.
    expect(() => assertAgentCredential("claude-agent-sdk")).not.toThrow();
    expect(() => assertAgentCredential("pi")).not.toThrow();
  });

  it("accepts a codex local route backed by a Codex subscription login", () => {
    setLoadedConfig({ projects: [], ai: { mode: "local", provider: "local" } });
    writeFileSync(join(emptyCodexHome, "auth.json"), "{}");
    expect(() => assertAgentCredential("codex")).not.toThrow();
  });

  it("fails closed for a codex local route with no Codex login even when an ambient key is exported", () => {
    setLoadedConfig({ projects: [], ai: { mode: "local", provider: "local" } });
    process.env.OPENAI_API_KEY = "sk-ambient-for-other-tools";
    // The saved local route is an explicit subscription-auth choice. An
    // unrelated ambient key must not silently reroute the run through the
    // gateway; reject before scanning starts instead.
    expect(() => assertAgentCredential("codex")).toThrow(/codex login/);
    expect(() => assertAgentCredential("codex")).toThrow(/--model-auth gateway/);
  });

  it("fails preflight (not mid-run) for a codex local route with no login and no key", () => {
    setLoadedConfig({ projects: [], ai: { mode: "local", provider: "local" } });
    expect(() => assertAgentCredential("codex")).toThrow(/codex login/);
    expect(() => assertAgentCredential("codex")).toThrow(/--model-auth gateway/);
    expect(() => assertAgentCredential("codex")).not.toThrow(/OPENAI_API_KEY/);
  });

  it("accepts a codex login under $HOME and the backend resolves the same file", () => {
    mkdirSync(join(emptyCodexHome, ".codex"), { recursive: true });
    writeFileSync(join(emptyCodexHome, ".codex", "auth.json"), "{}");
    expect(() => assertAgentCredential("codex")).not.toThrow();
    expect(resolveCodexAuth({}).subscriptionHome).toBe(join(emptyCodexHome, ".codex"));
  });

  it("resolves a login under USERPROFILE when HOME is unset, like the backend", () => {
    // HOME can diverge from the OS home (sudo -E, systemd/launchd units, CI
    // jobs that override HOME). Preflight and the backend must agree on the
    // login location, or preflight accepts a login the backend cannot find.
    const userHome = mkdtempSync(join(tmpdir(), "deepsec-user-home-"));
    try {
      mkdirSync(join(userHome, ".codex"), { recursive: true });
      writeFileSync(join(userHome, ".codex", "auth.json"), "{}");
      delete process.env.HOME;
      delete process.env.CODEX_HOME;
      process.env.USERPROFILE = userHome;

      expect(() => assertAgentCredential("codex")).not.toThrow();
      expect(resolveCodexAuth({}).subscriptionHome).toBe(join(userHome, ".codex"));
    } finally {
      rmSync(userHome, { recursive: true, force: true });
    }
  });

  it("accepts a Codex login under USERPROFILE when HOME points elsewhere", () => {
    // Windows shells can set HOME (Git/MSYS) away from the real profile.
    // Preflight and the backend must probe both locations, or a valid
    // %USERPROFILE%\.codex login is missed and the local route fails closed.
    const bareHome = mkdtempSync(join(tmpdir(), "deepsec-bare-home-"));
    const userHome = mkdtempSync(join(tmpdir(), "deepsec-user-home-"));
    try {
      mkdirSync(join(userHome, ".codex"), { recursive: true });
      writeFileSync(join(userHome, ".codex", "auth.json"), "{}");
      delete process.env.CODEX_HOME;
      process.env.HOME = bareHome;
      process.env.USERPROFILE = userHome;

      expect(() => assertAgentCredential("codex")).not.toThrow();
      expect(resolveCodexAuth({}).subscriptionHome).toBe(join(userHome, ".codex"));

      setLoadedConfig({ projects: [], ai: { mode: "local", provider: "local" } });
      expect(() => assertAgentCredential("codex")).not.toThrow();
      expect(resolveCodexAuth({ modelAuth: "local" }).mode).toBe("subscription");
    } finally {
      rmSync(bareHome, { recursive: true, force: true });
      rmSync(userHome, { recursive: true, force: true });
    }
  });

  it("accepts a per-run gateway override on a saved local route", () => {
    setLoadedConfig({ projects: [], ai: { mode: "local", provider: "local" } });
    process.env.AI_GATEWAY_API_KEY = "vck_gateway";
    expect(() =>
      assertAgentCredential("codex", { modelRoute: { mode: "gateway", provider: "vercel" } }),
    ).not.toThrow();
  });

  it("accepts a per-run local override even when the saved route is gateway", () => {
    setLoadedConfig({ projects: [], ai: { mode: "gateway", provider: "vercel" } });
    writeFileSync(join(emptyCodexHome, "auth.json"), "{}");
    expect(() =>
      assertAgentCredential("codex", { modelRoute: { mode: "local", provider: "local" } }),
    ).not.toThrow();
  });

  it("uses the brokered token for a saved local route inside a sandbox worker", () => {
    setLoadedConfig({ projects: [], ai: { mode: "local", provider: "local" } });
    process.env.DEEPSEC_INSIDE_SANDBOX = "1";
    process.env.OPENAI_API_KEY = "deepsec-sandbox-brokered-credential";
    expect(() => assertAgentCredential("codex")).not.toThrow();
  });

  it("still requires a brokered token inside a sandbox worker with a local route", () => {
    setLoadedConfig({ projects: [], ai: { mode: "local", provider: "local" } });
    process.env.DEEPSEC_INSIDE_SANDBOX = "1";
    // No machine-wide login is honored in the worker, and the saved local
    // route must not turn into a "codex login" error there: the brokered
    // token is the sandbox credential route.
    expect(() => assertAgentCredential("codex")).toThrow(/AI_GATEWAY_API_KEY/);
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

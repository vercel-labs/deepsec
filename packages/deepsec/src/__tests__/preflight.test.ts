import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  applyAiGatewayDefaults,
  assertAgentCredential,
  assertSandboxCredential,
} from "../preflight.js";

describe("assertAgentCredential", () => {
  let saved: Record<string, string | undefined>;
  let emptyClaudeHome: string;
  let emptyCodexHome: string;
  let emptyPathDir: string;
  beforeEach(() => {
    saved = {
      ANTHROPIC_AUTH_TOKEN: process.env.ANTHROPIC_AUTH_TOKEN,
      OPENAI_API_KEY: process.env.OPENAI_API_KEY,
      CLAUDE_HOME: process.env.CLAUDE_HOME,
      CODEX_HOME: process.env.CODEX_HOME,
      PATH: process.env.PATH,
    };
    delete process.env.ANTHROPIC_AUTH_TOKEN;
    delete process.env.OPENAI_API_KEY;
    // Point CLAUDE_HOME / CODEX_HOME and PATH at empty tmp dirs so the
    // suite is hermetic — the dev running tests may have a real
    // ~/.codex/auth.json or `claude` on $PATH, which would cause
    // "no token" tests to incorrectly pass.
    emptyClaudeHome = mkdtempSync(join(tmpdir(), "deepsec-claude-home-"));
    emptyCodexHome = mkdtempSync(join(tmpdir(), "deepsec-codex-home-"));
    emptyPathDir = mkdtempSync(join(tmpdir(), "deepsec-empty-path-"));
    process.env.CLAUDE_HOME = emptyClaudeHome;
    process.env.CODEX_HOME = emptyCodexHome;
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
  });

  it("passes for claude-agent-sdk when ANTHROPIC_AUTH_TOKEN is set", () => {
    process.env.ANTHROPIC_AUTH_TOKEN = "x";
    expect(() => assertAgentCredential("claude-agent-sdk")).not.toThrow();
  });

  it("throws actionable message for claude-agent-sdk when no token and no claude CLI", () => {
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

  it("skips Deepsec-managed credential checks for ACP agents", () => {
    // ACP bridges own their auth flow (for example, local Atlas/Alta login),
    // so missing Claude/OpenAI env vars should not block --agent acp.
    expect(() => assertAgentCredential("acp")).not.toThrow();
    expect(() => assertAgentCredential("acp", { inSandbox: true })).not.toThrow();
  });

  it("skips the credential check for custom plugin agents", () => {
    // Tests use this so a stub agent registered via plugins[] doesn't
    // require fake ANTHROPIC_AUTH_TOKEN env vars.
    expect(() => assertAgentCredential("stub")).not.toThrow();
    expect(() => assertAgentCredential("anything-else")).not.toThrow();
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
  });

  it("does nothing when AI_GATEWAY_API_KEY is unset", () => {
    applyAiGatewayDefaults();
    expect(process.env.ANTHROPIC_AUTH_TOKEN).toBeUndefined();
    expect(process.env.OPENAI_API_KEY).toBeUndefined();
    expect(process.env.ANTHROPIC_BASE_URL).toBeUndefined();
    expect(process.env.OPENAI_BASE_URL).toBeUndefined();
  });

  it("populates all four vars from AI_GATEWAY_API_KEY", () => {
    process.env.AI_GATEWAY_API_KEY = "gw-key";
    applyAiGatewayDefaults();
    expect(process.env.ANTHROPIC_AUTH_TOKEN).toBe("gw-key");
    expect(process.env.OPENAI_API_KEY).toBe("gw-key");
    expect(process.env.ANTHROPIC_BASE_URL).toBe("https://ai-gateway.vercel.sh");
    expect(process.env.OPENAI_BASE_URL).toBe("https://ai-gateway.vercel.sh/v1");
  });

  it("does not overwrite explicit ANTHROPIC_AUTH_TOKEN", () => {
    process.env.AI_GATEWAY_API_KEY = "gw-key";
    process.env.ANTHROPIC_AUTH_TOKEN = "explicit-anthropic";
    applyAiGatewayDefaults();
    expect(process.env.ANTHROPIC_AUTH_TOKEN).toBe("explicit-anthropic");
    expect(process.env.OPENAI_API_KEY).toBe("gw-key");
  });

  it("does not overwrite an explicit ANTHROPIC_BASE_URL pointing direct-to-provider", () => {
    process.env.AI_GATEWAY_API_KEY = "gw-key";
    process.env.ANTHROPIC_BASE_URL = "https://api.anthropic.com";
    applyAiGatewayDefaults();
    expect(process.env.ANTHROPIC_BASE_URL).toBe("https://api.anthropic.com");
    expect(process.env.OPENAI_BASE_URL).toBe("https://ai-gateway.vercel.sh/v1");
  });
});

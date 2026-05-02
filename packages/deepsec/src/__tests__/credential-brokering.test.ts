import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildSandboxEnv, resolveBrokeredCredentials } from "../sandbox/setup.js";

const TOUCHED_KEYS = [
  "ANTHROPIC_AUTH_TOKEN",
  "ANTHROPIC_BASE_URL",
  "OPENAI_API_KEY",
  "OPENAI_BASE_URL",
] as const;

describe("credential brokering", () => {
  let saved: Record<string, string | undefined> = {};

  beforeEach(() => {
    saved = {};
    for (const k of TOUCHED_KEYS) {
      saved[k] = process.env[k];
      delete process.env[k];
    }
  });

  afterEach(() => {
    for (const k of TOUCHED_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  describe("resolveBrokeredCredentials", () => {
    it("captures ANTHROPIC_AUTH_TOKEN from the orchestrator env", () => {
      process.env.ANTHROPIC_AUTH_TOKEN = "vck_real";
      const c = resolveBrokeredCredentials("claude-agent-sdk");
      expect(c.anthropicToken).toBe("vck_real");
      expect(c.openaiToken).toBeUndefined();
    });

    it("falls back to ANTHROPIC token for OpenAI on the codex path", () => {
      process.env.ANTHROPIC_AUTH_TOKEN = "vck_real";
      const c = resolveBrokeredCredentials("codex");
      expect(c.openaiToken).toBe("vck_real");
    });

    it("does not borrow ANTHROPIC token for OpenAI off the codex path", () => {
      process.env.ANTHROPIC_AUTH_TOKEN = "vck_real";
      const c = resolveBrokeredCredentials("claude-agent-sdk");
      expect(c.openaiToken).toBeUndefined();
    });

    it("prefers an explicit OPENAI_API_KEY over the anthropic fallback", () => {
      process.env.ANTHROPIC_AUTH_TOKEN = "vck_anthropic";
      process.env.OPENAI_API_KEY = "sk-explicit";
      const c = resolveBrokeredCredentials("codex");
      expect(c.openaiToken).toBe("sk-explicit");
    });
  });

  describe("buildSandboxEnv (the env handed to Sandbox.create)", () => {
    it("never contains a real ANTHROPIC token", () => {
      process.env.ANTHROPIC_AUTH_TOKEN = "vck_supersecret_realvalue";
      process.env.ANTHROPIC_BASE_URL = "https://ai-gateway.vercel.sh";
      const credentials = resolveBrokeredCredentials("claude-agent-sdk");
      const env = buildSandboxEnv("claude-agent-sdk", credentials);

      // The placeholder is set so the SDK can construct, but the real
      // token does not appear anywhere in the env map.
      expect(env.ANTHROPIC_AUTH_TOKEN).toBeDefined();
      expect(env.ANTHROPIC_AUTH_TOKEN).not.toBe("vck_supersecret_realvalue");
      for (const v of Object.values(env)) {
        expect(v).not.toContain("vck_supersecret_realvalue");
      }
    });

    it("never contains a real OPENAI key on the codex path", () => {
      process.env.OPENAI_API_KEY = "sk-real-openai-secret";
      process.env.OPENAI_BASE_URL = "https://api.openai.com";
      const credentials = resolveBrokeredCredentials("codex");
      const env = buildSandboxEnv("codex", credentials);

      expect(env.OPENAI_API_KEY).toBeDefined();
      expect(env.OPENAI_API_KEY).not.toBe("sk-real-openai-secret");
      for (const v of Object.values(env)) {
        expect(v).not.toContain("sk-real-openai-secret");
      }
    });

    it("omits the placeholder when the orchestrator has no token to broker", () => {
      // No ANTHROPIC_AUTH_TOKEN set — SDK should fail fast at init rather
      // than 401 from upstream after a brokered placeholder gets through.
      const credentials = resolveBrokeredCredentials("claude-agent-sdk");
      const env = buildSandboxEnv("claude-agent-sdk", credentials);
      expect(env.ANTHROPIC_AUTH_TOKEN).toBeUndefined();
    });

    it("preserves routing env (base URLs) so the agent knows where to send traffic", () => {
      process.env.ANTHROPIC_AUTH_TOKEN = "vck_real";
      process.env.ANTHROPIC_BASE_URL = "https://ai-gateway.vercel.sh";
      const credentials = resolveBrokeredCredentials("claude-agent-sdk");
      const env = buildSandboxEnv("claude-agent-sdk", credentials);

      // ANTHROPIC_BASE_URL gets rewritten to the local proxy by buildSandboxEnv
      // so the agent talks to the in-VM proxy. The original is exposed as
      // ANTHROPIC_UPSTREAM_BASE_URL for the proxy to forward to.
      expect(env.ANTHROPIC_UPSTREAM_BASE_URL).toBe("https://ai-gateway.vercel.sh");
      expect(env.ANTHROPIC_BASE_URL).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
    });
  });
});

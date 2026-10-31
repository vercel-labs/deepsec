import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildClaudeEnv } from "../agents/claude-agent-sdk.js";
import { buildGatewayProviderConfig } from "../agents/codex-sdk.js";

// App Attribution wiring per backend: gateway-bound requests carry
// http-referer + x-title; direct-provider requests carry nothing.
// (The version-stamped title itself is covered in shared.test.ts.)

const KEYS = [
  "ANTHROPIC_API_KEY",
  "ANTHROPIC_AUTH_TOKEN",
  "ANTHROPIC_BASE_URL",
  "ANTHROPIC_CUSTOM_HEADERS",
  "CLAUDE_CODE_OAUTH_TOKEN",
] as const;
const saved: Record<string, string | undefined> = {};

beforeEach(() => {
  for (const k of KEYS) saved[k] = process.env[k];
  for (const k of KEYS) delete process.env[k];
});
afterEach(() => {
  for (const k of KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
});

describe("buildClaudeEnv attribution", () => {
  it("sets ANTHROPIC_CUSTOM_HEADERS when the base URL is the gateway", () => {
    process.env.ANTHROPIC_BASE_URL = "https://ai-gateway.vercel.sh";
    process.env.ANTHROPIC_AUTH_TOKEN = "vck_x";
    const env = buildClaudeEnv();
    expect(env.ANTHROPIC_CUSTOM_HEADERS).toContain("http-referer: https://deepsec.sh");
    expect(env.ANTHROPIC_CUSTOM_HEADERS).toMatch(/x-title: deepsec/);
  });

  it("omits ANTHROPIC_CUSTOM_HEADERS for direct-Anthropic runs", () => {
    process.env.ANTHROPIC_BASE_URL = "https://api.anthropic.com";
    process.env.ANTHROPIC_API_KEY = "sk-ant-x";
    expect(buildClaudeEnv().ANTHROPIC_CUSTOM_HEADERS).toBeUndefined();
  });

  it("omits ANTHROPIC_CUSTOM_HEADERS when no base URL is set (subscription mode)", () => {
    expect(buildClaudeEnv().ANTHROPIC_CUSTOM_HEADERS).toBeUndefined();
  });

  it("appends to a user-supplied ANTHROPIC_CUSTOM_HEADERS instead of clobbering", () => {
    process.env.ANTHROPIC_BASE_URL = "https://ai-gateway.vercel.sh";
    process.env.ANTHROPIC_CUSTOM_HEADERS = "x-custom: keep-me";
    const value = buildClaudeEnv().ANTHROPIC_CUSTOM_HEADERS ?? "";
    expect(value).toContain("x-custom: keep-me");
    expect(value).toContain("http-referer: https://deepsec.sh");
    expect(value.indexOf("x-custom")).toBe(0);
  });

  it("lets a user-set attribution header win over ours", () => {
    process.env.ANTHROPIC_BASE_URL = "https://ai-gateway.vercel.sh";
    process.env.ANTHROPIC_CUSTOM_HEADERS = "X-Title: my-own-app";
    const value = buildClaudeEnv().ANTHROPIC_CUSTOM_HEADERS ?? "";
    expect(value).toContain("X-Title: my-own-app");
    // Our x-title must not be added alongside the user's (name match is
    // case-insensitive); http-referer is still ours to add.
    expect(value.match(/x-title/gi)).toHaveLength(1);
    expect(value).toContain("http-referer: https://deepsec.sh");
  });
});

describe("buildGatewayProviderConfig attribution", () => {
  it("adds http_headers for the gateway base URL (either form)", () => {
    for (const url of ["https://ai-gateway.vercel.sh", "https://ai-gateway.vercel.sh/v1"]) {
      const config = buildGatewayProviderConfig(url);
      expect(config.base_url).toBe("https://ai-gateway.vercel.sh/v1");
      expect(config.http_headers).toMatchObject({
        "http-referer": "https://deepsec.sh",
      });
    }
  });

  it("omits http_headers for direct-provider base URLs", () => {
    const config = buildGatewayProviderConfig("https://api.openai.com/v1");
    expect(config.http_headers).toBeUndefined();
  });

  it("omits http_headers when no base URL is configured", () => {
    expect(buildGatewayProviderConfig(undefined).http_headers).toBeUndefined();
  });
});

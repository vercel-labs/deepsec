import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildClaudeEnv } from "../agents/claude-agent-sdk.js";

// Claude-on-Vertex routing. The claude backend reaches Vertex through Claude
// Code's own env vars (GCP ADC). buildClaudeEnv forwards only the routing vars,
// and only when the operator opted in with CLAUDE_CODE_USE_VERTEX. It never
// forwards credential-file pointers, and the allowlist still drops everything
// else (e.g. GITHUB_TOKEN).

const KEYS = [
  "CLAUDE_CODE_USE_VERTEX",
  "ANTHROPIC_VERTEX_PROJECT_ID",
  "GOOGLE_CLOUD_PROJECT",
  "GCLOUD_PROJECT",
  "CLOUD_ML_REGION",
  "GOOGLE_APPLICATION_CREDENTIALS",
  "CLOUDSDK_CONFIG",
  "CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS",
  "VERTEX_REGION_CLAUDE_SONNET_4_6",
  "GITHUB_TOKEN",
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

describe("buildClaudeEnv — Vertex routing", () => {
  it("forwards the routing vars when CLAUDE_CODE_USE_VERTEX is set", () => {
    process.env.CLAUDE_CODE_USE_VERTEX = "1";
    process.env.ANTHROPIC_VERTEX_PROJECT_ID = "my-project";
    process.env.CLOUD_ML_REGION = "us-east5";
    process.env.CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS = "1";
    const env = buildClaudeEnv();
    expect(env.CLAUDE_CODE_USE_VERTEX).toBe("1");
    expect(env.ANTHROPIC_VERTEX_PROJECT_ID).toBe("my-project");
    expect(env.CLOUD_ML_REGION).toBe("us-east5");
    expect(env.CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS).toBe("1");
  });

  it("forwards dynamic per-model region overrides when Vertex is enabled", () => {
    process.env.CLAUDE_CODE_USE_VERTEX = "1";
    process.env.VERTEX_REGION_CLAUDE_SONNET_4_6 = "europe-west1";
    expect(buildClaudeEnv().VERTEX_REGION_CLAUDE_SONNET_4_6).toBe("europe-west1");
  });

  it("forwards nothing Vertex-related when CLAUDE_CODE_USE_VERTEX is unset", () => {
    process.env.ANTHROPIC_VERTEX_PROJECT_ID = "my-project";
    process.env.CLOUD_ML_REGION = "us-east5";
    process.env.VERTEX_REGION_CLAUDE_SONNET_4_6 = "us-east5";
    const env = buildClaudeEnv();
    expect(env.ANTHROPIC_VERTEX_PROJECT_ID).toBeUndefined();
    expect(env.CLOUD_ML_REGION).toBeUndefined();
    expect(env.VERTEX_REGION_CLAUDE_SONNET_4_6).toBeUndefined();
  });

  it("never forwards GCP credential-file pointers, even on a Vertex run", () => {
    process.env.CLAUDE_CODE_USE_VERTEX = "1";
    process.env.GOOGLE_APPLICATION_CREDENTIALS = "/path/sa.json";
    process.env.CLOUDSDK_CONFIG = "/path/gcloud";
    const env = buildClaudeEnv();
    expect(env.GOOGLE_APPLICATION_CREDENTIALS).toBeUndefined();
    expect(env.CLOUDSDK_CONFIG).toBeUndefined();
  });

  it("still drops non-allowlisted secrets", () => {
    process.env.CLAUDE_CODE_USE_VERTEX = "1";
    process.env.GITHUB_TOKEN = "ghp_should_not_leak";
    expect(buildClaudeEnv().GITHUB_TOKEN).toBeUndefined();
  });
});

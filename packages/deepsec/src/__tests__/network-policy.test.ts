import type { NetworkPolicy, NetworkPolicyRule } from "@vercel/sandbox";
import { describe, expect, it } from "vitest";
import { buildWorkerNetworkPolicy } from "../sandbox/setup.js";

function policyRecord(p: NetworkPolicy): Record<string, NetworkPolicyRule[]> {
  if (typeof p === "string") throw new Error("expected custom policy, got " + p);
  const a = p.allow;
  if (!a || Array.isArray(a)) throw new Error("expected record-form allow map");
  return a;
}

function allowedHosts(p: NetworkPolicy): string[] {
  return Object.keys(policyRecord(p)).sort();
}

function bearerFor(p: NetworkPolicy, host: string): string | null {
  const rules = policyRecord(p)[host];
  if (!rules) return null;
  for (const rule of rules) {
    for (const t of rule.transform ?? []) {
      const auth = t.headers?.authorization ?? t.headers?.Authorization;
      if (auth) return auth;
    }
  }
  return null;
}

describe("buildWorkerNetworkPolicy", () => {
  it("uses ANTHROPIC_UPSTREAM_BASE_URL host on the claude path", () => {
    const policy = buildWorkerNetworkPolicy(
      { ANTHROPIC_UPSTREAM_BASE_URL: "https://ai-gateway.vercel.sh" },
      "claude-agent-sdk",
    );
    expect(allowedHosts(policy)).toEqual(["ai-gateway.vercel.sh"]);
  });

  it("uses OPENAI_BASE_URL host on the codex path", () => {
    const policy = buildWorkerNetworkPolicy(
      { OPENAI_BASE_URL: "https://ai-gateway.vercel.sh/v1" },
      "codex",
    );
    expect(allowedHosts(policy)).toEqual(["ai-gateway.vercel.sh"]);
  });

  it("ignores ANTHROPIC_UPSTREAM_BASE_URL when agentType is codex", () => {
    const policy = buildWorkerNetworkPolicy(
      {
        ANTHROPIC_UPSTREAM_BASE_URL: "https://api.anthropic.com",
        OPENAI_BASE_URL: "https://api.openai.com",
      },
      "codex",
    );
    expect(allowedHosts(policy)).toEqual(["api.openai.com"]);
  });

  it("falls back to the provider default when no upstream URL is set", () => {
    const claudePolicy = buildWorkerNetworkPolicy({}, "claude-agent-sdk");
    expect(allowedHosts(claudePolicy)).toEqual(["api.anthropic.com"]);

    const codexPolicy = buildWorkerNetworkPolicy({}, "codex");
    expect(allowedHosts(codexPolicy)).toEqual(["api.openai.com"]);
  });

  it("falls back when the URL is unparseable", () => {
    const policy = buildWorkerNetworkPolicy(
      { ANTHROPIC_UPSTREAM_BASE_URL: "not a url" },
      "claude-agent-sdk",
    );
    expect(allowedHosts(policy)).toEqual(["api.anthropic.com"]);
  });

  it("merges extraAllowedHosts with the derived host", () => {
    const policy = buildWorkerNetworkPolicy(
      { ANTHROPIC_UPSTREAM_BASE_URL: "https://ai-gateway.vercel.sh" },
      "claude-agent-sdk",
      {},
      ["telemetry.example.com"],
    );
    expect(allowedHosts(policy)).toEqual(["ai-gateway.vercel.sh", "telemetry.example.com"]);
  });

  it("dedupes when extras overlap with the derived host", () => {
    const policy = buildWorkerNetworkPolicy(
      { ANTHROPIC_UPSTREAM_BASE_URL: "https://api.anthropic.com" },
      "claude-agent-sdk",
      {},
      ["api.anthropic.com"],
    );
    expect(allowedHosts(policy)).toEqual(["api.anthropic.com"]);
  });

  describe("credential brokering", () => {
    it("injects Authorization on the claude AI host when a token is provided", () => {
      const policy = buildWorkerNetworkPolicy(
        { ANTHROPIC_UPSTREAM_BASE_URL: "https://ai-gateway.vercel.sh" },
        "claude-agent-sdk",
        { anthropicToken: "vck_realtoken" },
      );
      expect(bearerFor(policy, "ai-gateway.vercel.sh")).toBe("Bearer vck_realtoken");
    });

    it("injects Authorization on the codex AI host when an OpenAI token is provided", () => {
      const policy = buildWorkerNetworkPolicy(
        { OPENAI_BASE_URL: "https://ai-gateway.vercel.sh/v1" },
        "codex",
        { openaiToken: "vck_realtoken" },
      );
      expect(bearerFor(policy, "ai-gateway.vercel.sh")).toBe("Bearer vck_realtoken");
    });

    it("emits no transform when no matching credential is provided", () => {
      const policy = buildWorkerNetworkPolicy(
        { ANTHROPIC_UPSTREAM_BASE_URL: "https://ai-gateway.vercel.sh" },
        "claude-agent-sdk",
        {},
      );
      expect(policyRecord(policy)["ai-gateway.vercel.sh"]).toEqual([]);
    });

    it("does not inject the anthropic token when running codex without an openai token", () => {
      // The anthropic-as-openai fallback happens at resolveBrokeredCredentials,
      // not here — this layer only sees what was passed in.
      const policy = buildWorkerNetworkPolicy(
        { OPENAI_BASE_URL: "https://api.openai.com" },
        "codex",
        { anthropicToken: "vck_realtoken" },
      );
      expect(bearerFor(policy, "api.openai.com")).toBeNull();
    });

    it("does not attach the transform to extra allowed hosts", () => {
      const policy = buildWorkerNetworkPolicy(
        { ANTHROPIC_UPSTREAM_BASE_URL: "https://ai-gateway.vercel.sh" },
        "claude-agent-sdk",
        { anthropicToken: "vck_realtoken" },
        ["telemetry.example.com"],
      );
      expect(bearerFor(policy, "ai-gateway.vercel.sh")).toBe("Bearer vck_realtoken");
      expect(bearerFor(policy, "telemetry.example.com")).toBeNull();
    });
  });
});

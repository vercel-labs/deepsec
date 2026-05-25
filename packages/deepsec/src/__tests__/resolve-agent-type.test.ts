import { defineConfig, setLoadedConfig } from "@deepsec/core";
import { afterEach, describe, expect, it } from "vitest";
import { resolveAgentType } from "../resolve-agent-type.js";

describe("resolveAgentType", () => {
  afterEach(() => {
    setLoadedConfig(defineConfig({ projects: [] }));
  });

  it("accepts the legacy claude-agent-sdk value", () => {
    setLoadedConfig(defineConfig({ projects: [], defaultAgent: "codex" }));
    expect(resolveAgentType("claude-agent-sdk")).toBe("claude-agent-sdk");
  });

  it("aliases claude to claude-agent-sdk", () => {
    expect(resolveAgentType("claude")).toBe("claude-agent-sdk");
  });

  it("aliases claude from defaultAgent config", () => {
    setLoadedConfig(defineConfig({ projects: [], defaultAgent: "claude" }));
    expect(resolveAgentType(undefined)).toBe("claude-agent-sdk");
  });

  it("falls back to defaultAgent from config when not provided", () => {
    setLoadedConfig(defineConfig({ projects: [], defaultAgent: "codex" }));
    expect(resolveAgentType(undefined)).toBe("codex");
  });

  it("falls back to codex when neither is set", () => {
    setLoadedConfig(defineConfig({ projects: [] }));
    expect(resolveAgentType(undefined)).toBe("codex");
  });

  it("passes cursor through unchanged", () => {
    expect(resolveAgentType("cursor")).toBe("cursor");
  });
});

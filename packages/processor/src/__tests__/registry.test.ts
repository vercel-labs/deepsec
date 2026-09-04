import { describe, expect, it } from "vitest";
import { AgentRegistry } from "../agents/registry.js";
import type {
  AgentPlugin,
  AgentProgress,
  InvestigateOutput,
  RevalidateOutput,
} from "../agents/types.js";
import { createDefaultAgentRegistry } from "../index.js";

function makeMockPlugin(type: string): AgentPlugin {
  return {
    type,
    async *investigate(): AsyncGenerator<AgentProgress, InvestigateOutput> {
      return { results: [], meta: { durationMs: 0 } };
    },
    async *revalidate(): AsyncGenerator<AgentProgress, RevalidateOutput> {
      return { verdicts: [], meta: { durationMs: 0 } };
    },
  };
}

describe("AgentRegistry", () => {
  it("registers and retrieves a plugin", () => {
    const registry = new AgentRegistry();
    const plugin = makeMockPlugin("test-agent");
    registry.register(plugin);
    expect(registry.get("test-agent")).toBe(plugin);
  });

  it("returns undefined for unregistered type", () => {
    const registry = new AgentRegistry();
    expect(registry.get("nonexistent")).toBeUndefined();
  });

  it("lists registered types", () => {
    const registry = new AgentRegistry();
    registry.register(makeMockPlugin("agent-a"));
    registry.register(makeMockPlugin("agent-b"));
    expect(registry.types()).toEqual(["agent-a", "agent-b"]);
  });

  it("overwrites plugin with same type", () => {
    const registry = new AgentRegistry();
    const first = makeMockPlugin("agent");
    const second = makeMockPlugin("agent");
    registry.register(first);
    registry.register(second);
    expect(registry.get("agent")).toBe(second);
    expect(registry.types()).toEqual(["agent"]);
  });
});

describe("createDefaultAgentRegistry", () => {
  it("registers built-in backends", () => {
    const registry = createDefaultAgentRegistry();
    expect(registry.get("claude-agent-sdk")).toBeDefined();
    expect(registry.get("codex")).toBeDefined();
    expect(registry.get("pi")).toBeDefined();
    expect(registry.get("grok")).toBeDefined();
    expect(registry.types().sort()).toEqual(["claude-agent-sdk", "codex", "grok", "pi"]);
  });
});

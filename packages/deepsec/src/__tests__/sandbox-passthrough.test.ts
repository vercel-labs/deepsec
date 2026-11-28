import { describe, expect, it } from "vitest";
import { extractFlag, normalizePassthroughArgs } from "../commands/sandbox-process.js";
import { buildSandboxInvocation } from "../sandbox/orchestrator.js";
import type { SandboxConfig } from "../sandbox/types.js";

// The worker splits each passthrough arg on whitespace and parses the tokens
// with commander, so the host must agree with it on the agent.
describe("sandbox agent selection", () => {
  it("reads passthrough flags the way the worker does", () => {
    const agentOf = (args: string[]) => extractFlag(normalizePassthroughArgs(args), "--agent");
    expect(agentOf(["--agent codex --agent fx"])).toBe("fx");
    expect(agentOf(["--agent=fx"])).toBe("fx");
  });

  it("ends the worker command with the agent the host validated", () => {
    const config = {
      command: "process",
      projectId: "app",
      agentType: "codex",
      extraArgs: ["--filter --agent", "fx"],
    } as unknown as SandboxConfig;
    const { args } = buildSandboxInvocation(config, "installed", null);
    expect(args.slice(-2)).toEqual(["--agent", "codex"]);
  });
});

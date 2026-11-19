import { describe, expect, it } from "vitest";
import { extractFlag, normalizePassthroughArgs } from "../commands/sandbox-process.js";

describe("sandbox passthrough agent selection", () => {
  // The worker splits each passthrough arg on whitespace and parses the
  // tokens with commander, so the host must see the same agent.
  const agentOf = (args: string[]) => extractFlag(normalizePassthroughArgs(args), "--agent");

  it("reads the agent from a single arg holding several tokens", () => {
    expect(agentOf(["--agent codex --agent fx"])).toBe("fx");
  });

  it("reads the --agent=value form", () => {
    expect(agentOf(["--agent=fx"])).toBe("fx");
  });

  it("uses the last occurrence, like commander", () => {
    expect(agentOf(["--agent", "codex", "--limit", "5", "--agent", "fx"])).toBe("fx");
  });

  it("ignores a flag with no value", () => {
    expect(agentOf(["--agent", "--force"])).toBeUndefined();
  });
});

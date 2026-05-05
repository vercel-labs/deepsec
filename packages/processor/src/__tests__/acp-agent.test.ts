import { EventEmitter } from "node:events";
import type { ChildProcessWithoutNullStreams } from "node:child_process";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildAcpInvocation, killAgent } from "../agents/acp-agent.js";

const registry = {
  version: "1.0.0",
  agents: [
    {
      id: "claude-acp",
      distribution: { npx: { package: "@agentclientprotocol/claude-agent-acp@0.32.0" } },
    },
    {
      id: "auggie",
      distribution: {
        npx: {
          package: "@augmentcode/auggie@0.25.2",
          args: ["--acp"],
          env: { AUGMENT_DISABLE_AUTO_UPDATE: "1" },
        },
      },
    },
    {
      id: "uv-agent",
      distribution: { uvx: { package: "uv-agent-acp", args: ["serve"], env: { UV_AGENT: "1" } } },
    },
    {
      id: "binary-agent",
      distribution: { binary: { "darwin-aarch64": { cmd: "./agent" } } },
    },
  ],
};

describe("ACP invocation resolution", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("requires an explicit ACP bridge selection", async () => {
    await expect(buildAcpInvocation("/repo", {})).rejects.toThrow(
      /ACP agent selection is required/,
    );
  });

  it("accepts a full custom command string", async () => {
    await expect(
      buildAcpInvocation("/repo", { acpCommand: "node ./server.js --stdio 'quoted arg'" }),
    ).resolves.toMatchObject({
      command: "node",
      args: ["./server.js", "--stdio", "quoted arg"],
      label: "node ./server.js --stdio 'quoted arg'",
    });
  });

  it("uses custom acpArgs without shell splitting", async () => {
    await expect(
      buildAcpInvocation("/repo", { acpCommand: "my-acp", acpArgs: ["serve", "--stdio value"] }),
    ).resolves.toMatchObject({ command: "my-acp", args: ["serve", "--stdio value"] });
  });

  it("resolves npx ACP registry agents", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({ ok: true, json: async () => registry })),
    );
    await expect(
      buildAcpInvocation("/repo", { acpRegistryAgent: "auggie", acpEnv: { EXTRA: "1" } }),
    ).resolves.toEqual({
      command: "npx",
      args: ["-y", "@augmentcode/auggie@0.25.2", "--acp"],
      env: { AUGMENT_DISABLE_AUTO_UPDATE: "1", EXTRA: "1" },
      label: "auggie via registry npx (@augmentcode/auggie@0.25.2)",
    });
  });

  it("resolves uvx ACP registry agents", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({ ok: true, json: async () => registry })),
    );
    await expect(buildAcpInvocation("/repo", { acpRegistryAgent: "uv-agent" })).resolves.toEqual({
      command: "uvx",
      args: ["uv-agent-acp", "serve"],
      env: { UV_AGENT: "1" },
      label: "uv-agent via registry uvx (uv-agent-acp)",
    });
  });

  it("gives an actionable error for binary-only registry agents", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({ ok: true, json: async () => registry })),
    );
    await expect(buildAcpInvocation("/repo", { acpRegistryAgent: "binary-agent" })).rejects.toThrow(
      /binary-only.*--acp-command\/--acp-args/,
    );
  });
});

class FakeChildProcess extends EventEmitter {
  exitCode: number | null = null;
  signalCode: NodeJS.Signals | null = null;
  killed = false;
  kill = vi.fn((signal?: NodeJS.Signals | number) => {
    this.killed = true;
    if (signal === "SIGTERM") return true;
    if (signal === "SIGKILL") {
      this.signalCode = "SIGKILL";
      this.emit("exit", null, "SIGKILL");
      return true;
    }
    return true;
  });
}

function killFakeAgent(child: FakeChildProcess): Promise<void> {
  return killAgent(child as unknown as ChildProcessWithoutNullStreams);
}

describe("ACP agent shutdown", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("escalates to SIGKILL when SIGTERM does not exit the bridge", async () => {
    vi.useFakeTimers();
    const child = new FakeChildProcess();

    const killed = killFakeAgent(child);
    await vi.advanceTimersByTimeAsync(100);
    await killed;

    expect(child.kill).toHaveBeenCalledTimes(2);
    expect(child.kill).toHaveBeenNthCalledWith(1, "SIGTERM");
    expect(child.kill).toHaveBeenNthCalledWith(2, "SIGKILL");
  });

  it("does not escalate when the bridge exits after SIGTERM", async () => {
    vi.useFakeTimers();
    const child = new FakeChildProcess();
    child.kill.mockImplementationOnce(() => {
      child.killed = true;
      setTimeout(() => {
        child.signalCode = "SIGTERM";
        child.emit("exit", null, "SIGTERM");
      }, 10);
      return true;
    });

    const killed = killFakeAgent(child);
    await vi.advanceTimersByTimeAsync(10);
    await killed;

    expect(child.kill).toHaveBeenCalledTimes(1);
    expect(child.kill).toHaveBeenCalledWith("SIGTERM");
  });
});

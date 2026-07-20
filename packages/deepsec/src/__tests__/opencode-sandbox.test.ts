import type { Sandbox } from "@vercel/sandbox";
import { describe, expect, it, vi } from "vitest";
import { DEEPSEC_DIR, ensureOpenCodeBinary } from "../sandbox/setup.js";

function commandResult(exitCode: number, stdout = "", stderr = "") {
  return {
    exitCode,
    stdout: async () => stdout,
    stderr: async () => stderr,
  };
}

describe("ensureOpenCodeBinary", () => {
  it.each([
    ["dev", `${DEEPSEC_DIR}/packages/deepsec/node_modules/opencode-ai/bin/opencode.exe`],
    ["installed", `${DEEPSEC_DIR}/node_modules/deepsec/node_modules/opencode-ai/bin/opencode.exe`],
  ] as const)("links the %s package binary onto PATH", async (mode, source) => {
    const runCommand = vi
      .fn()
      .mockResolvedValueOnce(commandResult(0))
      .mockResolvedValueOnce(commandResult(0, "1.18.3\n"));
    const onLog = vi.fn();

    await ensureOpenCodeBinary({ runCommand } as unknown as Sandbox, mode, onLog);

    expect(runCommand).toHaveBeenNthCalledWith(1, {
      cmd: "ln",
      args: ["-sfn", source, "/usr/local/bin/opencode"],
      sudo: true,
    });
    expect(runCommand).toHaveBeenNthCalledWith(2, {
      cmd: "opencode",
      args: ["--version"],
      cwd: DEEPSEC_DIR,
    });
    expect(onLog).toHaveBeenCalledWith("  1.18.3");
  });

  it("reports a failed system link before checking the binary", async () => {
    const runCommand = vi.fn().mockResolvedValue(commandResult(1, "", "permission denied"));

    await expect(
      ensureOpenCodeBinary({ runCommand } as unknown as Sandbox, "dev", vi.fn()),
    ).rejects.toThrow("OpenCode native binary link failed (exit 1): permission denied");
    expect(runCommand).toHaveBeenCalledTimes(1);
  });
});

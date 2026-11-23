import { APIError, StreamError } from "@vercel/sandbox";
import { describe, expect, it, vi } from "vitest";
import { isSandboxGone, waitForCommand } from "../sandbox/orchestrator.js";

const apiError = (status: number, json?: unknown) =>
  new APIError(new Response(null, { status }), {
    message: `Status code ${status} is not ok`,
    json,
  });

function cmd(results: Array<Error | { exitCode: number }>) {
  return {
    wait: vi.fn(async () => {
      const next = results.shift();
      if (!next) throw new Error("no more results");
      if (next instanceof Error) throw next;
      return next;
    }),
  };
}

describe("waitForCommand", () => {
  it("survives dropped connections by re-fetching the command", async () => {
    const first = cmd([new Error("fetch failed")]);
    const second = cmd([new Error("fetch failed"), { exitCode: 0 }]);
    const refetch = vi.fn(async () => second);
    const logs: string[] = [];
    const result = await waitForCommand(first, refetch, "[sandbox-1]", (m) => logs.push(m), {
      delayMs: 1,
    });
    expect(result).toEqual({ exitCode: 0 });
    expect(refetch).toHaveBeenCalledTimes(2);
    expect(logs).toHaveLength(2);
    expect(logs[0]).toContain("fetch failed");
  });

  it("gives up after the configured attempts", async () => {
    const c = cmd([new Error("a"), new Error("b"), new Error("c")]);
    await expect(
      waitForCommand(
        c,
        async () => c,
        "[sandbox-2]",
        () => {},
        { attempts: 3, delayMs: 1 },
      ),
    ).rejects.toThrow("c");
    expect(c.wait).toHaveBeenCalledTimes(3);
  });

  it("returns a real non-zero exit unchanged", async () => {
    const c = cmd([{ exitCode: 1 }]);
    const refetch = vi.fn();
    await expect(waitForCommand(c, refetch, "[s]", () => {})).resolves.toEqual({ exitCode: 1 });
    expect(refetch).not.toHaveBeenCalled();
  });

  it("gives up at once when the sandbox is gone (410)", async () => {
    const c = cmd([apiError(410), { exitCode: 0 }]);
    const refetch = vi.fn(async () => c);
    await expect(waitForCommand(c, refetch, "[s]", () => {}, { delayMs: 1 })).rejects.toThrow(
      "410",
    );
    expect(c.wait).toHaveBeenCalledTimes(1);
    expect(refetch).not.toHaveBeenCalled();
  });
});

describe("isSandboxGone", () => {
  it("recognizes the structured errors the SDK throws for a vanished sandbox", () => {
    expect(isSandboxGone(apiError(410))).toBe(true);
    // A 404 can come from a command or file lookup on a live sandbox.
    expect(isSandboxGone(apiError(404))).toBe(false);
    expect(isSandboxGone(apiError(400, { error: { code: "sandbox_stopped" } }))).toBe(true);
    expect(isSandboxGone(new StreamError("sandbox_stopped", "Sandbox stopped", "sbx_1"))).toBe(
      true,
    );
    expect(isSandboxGone(new Error("download failed", { cause: apiError(410) }))).toBe(true);
    expect(isSandboxGone(apiError(500))).toBe(false);
    expect(isSandboxGone(new Error("fetch failed"))).toBe(false);
    expect(isSandboxGone(undefined)).toBe(false);
  });

  it("ignores message text, which can come from inside the sandbox", () => {
    expect(isSandboxGone(new Error("Status code 410 is not ok"))).toBe(false);
    expect(
      isSandboxGone(
        new Error("sandbox_stopped: Sandbox has stopped execution and is no longer available"),
      ),
    ).toBe(false);
    expect(isSandboxGone("Exit code 1: Status code 410 is not ok")).toBe(false);
    expect(
      isSandboxGone(
        new Error("[sandbox-0] tar failed (exit 2): sandbox_stopped no longer available"),
      ),
    ).toBe(false);
  });
});

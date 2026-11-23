import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({ stops: [] as string[] }));

vi.mock("@vercel/sandbox", async (orig) => {
  const actual = await orig<typeof import("@vercel/sandbox")>();
  const exitCodes: Record<string, number> = { ok: 0, failed: 1, dlfail: 0 };
  return {
    ...actual,
    Sandbox: {
      get: async ({ sandboxId }: { sandboxId: string }) => {
        if (sandboxId === "gone")
          throw new actual.APIError(new Response(null, { status: 410 }), {
            message: "Status code 410 is not ok",
          });
        if (sandboxId === "unreachable") throw new Error("fetch failed");
        return {
          sandboxId,
          getCommand: async () => ({ exitCode: exitCodes[sandboxId], async *logs() {} }),
          stop: async () => {
            h.stops.push(sandboxId);
          },
        };
      },
    },
  };
});

vi.mock("../sandbox/download.js", () => ({
  downloadResults: async (sandbox: { sandboxId: string }) => {
    if (sandbox.sandboxId === "dlfail") throw new Error("tar failed");
    return 0;
  },
}));

const { collect } = await import("../sandbox/orchestrator.js");
const { loadRunState, saveRunState } = await import("../sandbox/state.js");

describe("collect", () => {
  let prev: string | undefined;
  let tmp: string;

  beforeEach(() => {
    prev = process.env.DEEPSEC_DATA_ROOT;
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-collect-"));
    process.env.DEEPSEC_DATA_ROOT = tmp;
    h.stops = [];
  });

  afterEach(() => {
    if (prev === undefined) delete process.env.DEEPSEC_DATA_ROOT;
    else process.env.DEEPSEC_DATA_ROOT = prev;
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it("keeps only the sandboxes a later collect can still act on", async () => {
    const runId = "sbx-20261122000000-0123456789abcdef";
    const ids = ["ok", "failed", "dlfail", "gone", "unreachable"];
    saveRunState({
      runId,
      projectId: "p",
      command: "process",
      vcpus: 2,
      launchedAt: new Date().toISOString(),
      sandboxes: ids.map((sandboxId, index) => ({
        sandboxId,
        cmdId: `cmd_${sandboxId}`,
        index,
        manifest: [`${sandboxId}.ts`],
      })),
      reserved: [{ index: 9, manifest: ["never-dispatched.ts"] }],
    });

    const logs: string[] = [];
    const results = await collect("p", runId, (m) => logs.push(m));

    expect(results.map((r) => r.success)).toEqual([true, false, false, false, false]);
    // Finished and salvaged sandboxes were stopped; the one whose download
    // failed is left running for another try.
    expect(h.stops.sort()).toEqual(["failed", "ok"]);
    const left = loadRunState("p", runId);
    expect(left.sandboxes.map((e) => e.sandboxId).sort()).toEqual(["dlfail", "unreachable"]);
    expect(left.reserved).toEqual([]);
    expect(logs.at(-1)).toMatch(/keeping 2 in the run state/);
  });
});

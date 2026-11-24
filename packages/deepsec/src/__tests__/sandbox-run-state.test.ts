import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { deleteRunState, loadRunState, saveRunState, updateRunState } from "../sandbox/state.js";
import type { SandboxRunState } from "../sandbox/types.js";

describe("sandbox run state for attached runs", () => {
  let prev: string | undefined;
  let tmp: string;

  beforeEach(() => {
    prev = process.env.DEEPSEC_DATA_ROOT;
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-runstate-"));
    process.env.DEEPSEC_DATA_ROOT = tmp;
  });

  afterEach(() => {
    if (prev === undefined) delete process.env.DEEPSEC_DATA_ROOT;
    else process.env.DEEPSEC_DATA_ROOT = prev;
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  function state(): SandboxRunState {
    return {
      runId: "sbx-20261119000000-0000000000000000",
      projectId: "p",
      command: "process",
      vcpus: 2,
      launchedAt: new Date(0).toISOString(),
      sandboxes: [
        { sandboxId: "sbx_a", cmdId: "cmd_a", index: 0, manifest: ["a.ts"] },
        { sandboxId: "sbx_b", cmdId: "cmd_b", index: 1, manifest: ["b.ts"] },
      ],
    };
  }

  it("shrinks the saved state as sandboxes finish, leaving only what collect still needs", () => {
    const s = state();
    saveRunState(s);
    s.sandboxes = s.sandboxes.filter((e) => e.index !== 0);
    updateRunState(s);
    expect(loadRunState("p", s.runId).sandboxes.map((e) => e.sandboxId)).toEqual(["sbx_b"]);
    const dir = path.dirname(path.join(tmp, "p", "sandbox-runs", "x"));
    expect(fs.readdirSync(dir).filter((f) => f.endsWith(".tmp"))).toEqual([]);
    deleteRunState("p", s.runId);
    expect(() => loadRunState("p", s.runId)).toThrow();
  });
});

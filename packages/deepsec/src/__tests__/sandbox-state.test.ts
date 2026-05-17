import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { listRunStates, loadRunState, saveRunState } from "../sandbox/state.js";
import type { SandboxRunState } from "../sandbox/types.js";

let dataRoot: string;

beforeEach(() => {
  dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-sandbox-state-"));
  process.env.DEEPSEC_DATA_ROOT = dataRoot;
});

afterEach(() => {
  fs.rmSync(dataRoot, { recursive: true, force: true });
  delete process.env.DEEPSEC_DATA_ROOT;
});

function state(overrides: Partial<SandboxRunState> = {}): SandboxRunState {
  return {
    runId: "sbx-20260516010101-aaaaaaaaaaaaaaaa",
    projectId: "project",
    command: "process",
    vcpus: 2,
    launchedAt: "2026-05-16T01:01:01.000Z",
    sandboxes: [
      {
        sandboxId: "sandbox-1",
        cmdId: "cmd-1",
        index: 0,
        manifest: ["src/a.ts"],
      },
    ],
    ...overrides,
  };
}

function statePath(projectId: string, runId: string): string {
  return path.join(dataRoot, projectId, "sandbox-runs", `${runId}.json`);
}

describe("sandbox run state validation", () => {
  it("round-trips a valid run state", () => {
    const s = state();
    saveRunState(s);

    expect(loadRunState(s.projectId, s.runId)).toEqual(s);
    expect(listRunStates(s.projectId).map((r) => r.runId)).toEqual([s.runId]);
  });

  it("rejects embedded projectId mismatches on load", () => {
    const s = state({ projectId: "other" });
    const p = statePath("project", s.runId);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, JSON.stringify(s));

    expect(() => loadRunState("project", s.runId)).toThrow(/projectId mismatch/);
  });

  it("rejects unsafe manifest entries and duplicate sandbox indexes", () => {
    expect(() =>
      saveRunState(
        state({
          sandboxes: [{ sandboxId: "sandbox-1", cmdId: "cmd-1", index: 0, manifest: ["../x"] }],
        }),
      ),
    ).toThrow(/Invalid filePath/);

    expect(() =>
      saveRunState(
        state({
          sandboxes: [
            { sandboxId: "sandbox-1", cmdId: "cmd-1", index: 0, manifest: ["a.ts"] },
            { sandboxId: "sandbox-2", cmdId: "cmd-2", index: 0, manifest: ["b.ts"] },
          ],
        }),
      ),
    ).toThrow(/duplicate index/);
  });

  it("listRunStates drops malformed or mismatched states", () => {
    const valid = state();
    saveRunState(valid);

    const badRunId = "sbx-20260516010102-bbbbbbbbbbbbbbbb";
    const badPath = statePath("project", badRunId);
    fs.writeFileSync(badPath, JSON.stringify(state({ runId: badRunId, projectId: "other" })));

    expect(listRunStates("project").map((r) => r.runId)).toEqual([valid.runId]);
  });
});

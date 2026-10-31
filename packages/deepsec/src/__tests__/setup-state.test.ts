import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  completePhase,
  createSetupState,
  digest,
  isCheckpointCurrent,
  readSetupState,
  startPhase,
} from "../setup/state.js";
import { buildSetupStatus } from "../setup/status.js";

const originalCwd = process.cwd();
afterEach(() => process.chdir(originalCwd));

describe("setup state", () => {
  it("writes atomic resumable checkpoints and invalidates changed inputs", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-setup-state-"));
    process.chdir(root);
    const state = createSetupState({
      projectId: "app",
      targetRoot: root,
      agentType: "codex",
      model: "model",
    });
    const input = digest({ package: 1 });
    startPhase(state, "install", input);
    completePhase(state, "install", digest("done"));

    const loaded = readSetupState("app");
    expect(loaded?.phases.install?.status).toBe("complete");
    expect(isCheckpointCurrent(loaded!, "install", input)).toBe(true);
    expect(isCheckpointCurrent(loaded!, "install", digest({ package: 2 }))).toBe(false);
    expect(
      (
        buildSetupStatus({ workspaceDir: root, projectId: "app", state: loaded }).phases as any[]
      ).find((phase) => phase.phase === "install"),
    ).toMatchObject({
      status: "stale",
      reason: expect.stringContaining("node_modules/deepsec"),
    });
  });
});

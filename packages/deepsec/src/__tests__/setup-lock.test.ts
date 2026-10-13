import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { acquireSetupLock } from "../setup/lock.js";
import { SetupProtocolError } from "../setup/protocol.js";

describe("setup workspace lock", () => {
  it("rejects a concurrent owner and can be reacquired after release", () => {
    const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-lock-"));
    const release = acquireSetupLock(workspace);
    expect(() => acquireSetupLock(workspace)).toThrow(SetupProtocolError);
    release();
    const releaseAgain = acquireSetupLock(workspace);
    releaseAgain();
  });

  it("reclaims a stale lock", () => {
    const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-stale-lock-"));
    fs.writeFileSync(
      path.join(workspace, ".deepsec-setup.lock"),
      JSON.stringify({ pid: 999_999_999, startedAt: "old", command: [] }),
    );
    const release = acquireSetupLock(workspace);
    release();
  });
});

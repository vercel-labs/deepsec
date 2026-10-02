import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";

const REPO_ROOT = path.resolve(__dirname, "../../../../");
const TSX = path.join(REPO_ROOT, "node_modules/.bin/tsx");
const REGISTER_HOOK = path.resolve(__dirname, "../run.ts");

/**
 * Spawn a child node that:
 *   1. Writes a "running" RunMeta to a temp data dir.
 *   2. Calls `registerActiveRun(...)` so the shutdown handler is installed.
 *   3. Prints "READY" and idles via setInterval.
 *
 * The test then sends the requested signal and waits for exit, with a
 * hard timeout so a regression (handler suppresses default termination
 * without providing an exit path → hang) shows up as a clear failure
 * instead of a hung suite.
 */
function spawnShutdownChild(opts: {
  dataRoot: string;
  projectId: string;
  runId: string;
}): Promise<{ child: ReturnType<typeof spawn>; ready: Promise<void> }> {
  const script = `
    import { registerActiveRun } from ${JSON.stringify(REGISTER_HOOK)};
    registerActiveRun(${JSON.stringify(opts.projectId)}, ${JSON.stringify(opts.runId)});
    process.stdout.write("READY\\n");
    // Keep the event loop alive so SIGINT actually has work to do.
    setInterval(() => {}, 1000);
  `;
  const child = spawn(TSX, ["-e", script], {
    env: { ...process.env, DEEPSEC_DATA_ROOT: opts.dataRoot },
    // detached: true puts the child in its own process group so that
    // process.kill(0, "SIGKILL") inside the child only kills the child's
    // group and does not propagate SIGKILL back to the test runner.
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const ready = new Promise<void>((resolve, reject) => {
    let buf = "";
    child.stdout.on("data", (chunk) => {
      buf += chunk.toString();
      if (buf.includes("READY")) resolve();
    });
    child.on("error", reject);
    child.on("exit", (code, signal) => {
      if (!buf.includes("READY")) {
        reject(new Error(`child exited before READY (code=${code} signal=${signal})`));
      }
    });
  });
  return Promise.resolve({ child, ready });
}

function waitForExit(
  child: ReturnType<typeof spawn>,
  timeoutMs: number,
): Promise<{ code: number | null; signal: NodeJS.Signals | null }> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`child did not exit within ${timeoutMs}ms (hang)`));
    }, timeoutMs);
    child.on("exit", (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal });
    });
  });
}

function writeRunningMeta(opts: { dataRoot: string; projectId: string; runId: string }): void {
  const runsDir = path.join(opts.dataRoot, opts.projectId, "runs");
  fs.mkdirSync(runsDir, { recursive: true });
  fs.writeFileSync(
    path.join(runsDir, `${opts.runId}.json`),
    JSON.stringify({
      runId: opts.runId,
      projectId: opts.projectId,
      rootPath: "/tmp",
      createdAt: new Date().toISOString(),
      type: "process",
      phase: "running",
      stats: {},
    }),
  );
}

describe("shutdown handler exit path", () => {
  it("kills the process on SIGINT", async () => {
    // The regression this guards: attaching a SIGINT listener
    // suppresses Node's default termination. If the listener doesn't
    // call process.exit (or kill), the process hangs after Ctrl+C.
    // The handler now uses process.kill(0, "SIGKILL") to guarantee
    // termination even when other listeners are registered.
    const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-shutdown-"));
    const projectId = "test-proj";
    const runId = "20260101000000-aaaaaaaaaaaaaaaa";
    writeRunningMeta({ dataRoot, projectId, runId });

    const { child, ready } = await spawnShutdownChild({ dataRoot, projectId, runId });
    await ready;
    child.kill("SIGINT");
    const { signal } = await waitForExit(child, 5000);
    // process.kill(0, "SIGKILL") terminates via SIGKILL, not a numeric exit code.
    expect(signal).toBe("SIGKILL");

    // And the run should have been flipped to error by the handler.
    const meta = JSON.parse(
      fs.readFileSync(path.join(dataRoot, projectId, "runs", `${runId}.json`), "utf-8"),
    );
    expect(meta.phase).toBe("error");
  });

  it("kills the process on SIGTERM", async () => {
    const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-shutdown-"));
    const projectId = "test-proj";
    const runId = "20260101000000-bbbbbbbbbbbbbbbb";
    writeRunningMeta({ dataRoot, projectId, runId });

    const { child, ready } = await spawnShutdownChild({ dataRoot, projectId, runId });
    await ready;
    child.kill("SIGTERM");
    const { signal } = await waitForExit(child, 5000);
    expect(signal).toBe("SIGKILL");
  });

  it("still flushes runs and kills the process even when another SIGINT listener is installed", async () => {
    // Previously the handler deferred to co-listeners (e.g. the sandbox
    // shutdown handler). This caused hangs when a co-listener (such as
    // an agent SDK) was registered but never called process.exit().
    // Now the handler always kills the process group via SIGKILL after
    // flushing run metadata, regardless of other listeners.
    const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-shutdown-"));
    const projectId = "test-proj";
    const runId = "20260101000000-cccccccccccccccc";
    writeRunningMeta({ dataRoot, projectId, runId });

    const script = `
      import { registerActiveRun } from ${JSON.stringify(REGISTER_HOOK)};
      registerActiveRun(${JSON.stringify(projectId)}, ${JSON.stringify(runId)});
      // Simulate a co-listener (e.g. agent SDK) that is registered but
      // never calls process.exit().
      process.on("SIGINT", () => { /* intentionally hangs */ });
      process.stdout.write("READY\\n");
      setInterval(() => {}, 1000);
    `;
    const child = spawn(TSX, ["-e", script], {
      env: { ...process.env, DEEPSEC_DATA_ROOT: dataRoot },
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    await new Promise<void>((resolve, reject) => {
      let buf = "";
      child.stdout.on("data", (c) => {
        buf += c.toString();
        if (buf.includes("READY")) resolve();
      });
      child.on("error", reject);
    });
    child.kill("SIGINT");
    const { signal } = await waitForExit(child, 5000);
    // SIGKILL guarantees termination even though the co-listener hangs.
    expect(signal).toBe("SIGKILL");

    // Run was still flipped to error before the kill.
    const meta = JSON.parse(
      fs.readFileSync(path.join(dataRoot, projectId, "runs", `${runId}.json`), "utf-8"),
    );
    expect(meta.phase).toBe("error");
  });
});

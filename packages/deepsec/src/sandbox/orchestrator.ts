import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { dataDir, getConfigPath, readProjectConfig } from "@deepsec/core";
import { Sandbox } from "@vercel/sandbox";
import { downloadResults } from "./download.js";
import { partitionFiles } from "./partitioner.js";
import {
  createBootstrapSnapshot,
  DEEPSEC_DIR,
  type DeepsecMode,
  spawnFromSnapshot,
  TARGET_DIR,
  type UploadBundle,
} from "./setup.js";
import { untrackSandbox } from "./shutdown.js";
import {
  deleteRunState,
  generateRunId,
  listRunStates,
  loadRunState,
  saveRunState,
} from "./state.js";
import type { SandboxConfig, SandboxInstance, SandboxResult, SandboxRunState } from "./types.js";
import { DATA_EXCLUDES, DEEPSEC_APP_EXCLUDES, makeTarball, TARGET_EXCLUDES } from "./upload.js";

/** Commands where we inject --root to point at the sandbox target checkout */
const NEEDS_ROOT = new Set(["process", "revalidate", "scan"]);

/**
 * Build the (cmd, args) pair to run a deepsec subcommand inside the sandbox.
 * Differs by mode: dev runs the source via tsx; installed runs the bin shim
 * left behind by `pnpm install` in the uploaded `.deepsec/` workspace.
 */
function buildSandboxInvocation(
  config: SandboxConfig,
  mode: DeepsecMode,
  manifestPath: string | null,
): { cmd: string; args: string[] } {
  const tail: string[] = [config.command, "--project-id", config.projectId];

  if (NEEDS_ROOT.has(config.command)) {
    tail.push("--root", TARGET_DIR);
  }
  if (manifestPath) {
    tail.push("--manifest", manifestPath);
  }
  for (const arg of config.extraArgs) {
    tail.push(...arg.split(/\s+/).filter(Boolean));
  }

  if (mode === "installed") {
    return { cmd: "node_modules/.bin/deepsec", args: tail };
  }
  return { cmd: "npx", args: ["tsx", "packages/deepsec/src/cli.ts", ...tail] };
}

const PARTITIONABLE_COMMANDS = new Set(["process", "revalidate"]);

// --- Upload prep ---

/**
 * Decide what directory to tarball as the "deepsec app" for sandbox upload,
 * and which CLI invocation pattern to use inside the sandbox. Two modes:
 *
 *   - **dev**: this CLI is running from the source repo (the deepsec package
 *     is found OUTSIDE any `node_modules/`). Tarball the source workspace
 *     root (the dir with `pnpm-workspace.yaml`) so the full monorepo +
 *     lockfile ship over. Workers run `tsx packages/deepsec/src/cli.ts`.
 *
 *   - **installed**: this CLI is running from `node_modules/deepsec/` inside
 *     a user's `.deepsec/` workspace. Tarball that workspace dir (parent of
 *     `deepsec.config.ts`) — it's a one-package npm project; the sandbox
 *     re-installs `deepsec` from npm. Workers run `node_modules/.bin/deepsec`.
 *
 * The deepsec package is identified by `package.json:name === "deepsec"`,
 * NOT by `pnpm-workspace.yaml`, so we don't accidentally pick the user's
 * parent monorepo if they happen to have one above `.deepsec/`.
 */
function resolveDeepsecAppContext(): { root: string; mode: DeepsecMode } {
  let dir = path.dirname(fileURLToPath(import.meta.url));
  while (dir !== path.dirname(dir)) {
    const pkgPath = path.join(dir, "package.json");
    if (fs.existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
        if (pkg.name === "deepsec") {
          if (dir.includes(`${path.sep}node_modules${path.sep}`)) {
            // Installed: ship the user's .deepsec/ workspace, not the
            // node_modules/deepsec package itself. The workspace has its
            // own package.json that depends on `deepsec`, so the sandbox
            // re-resolves it (no fragile node_modules tarball).
            const cfg = getConfigPath();
            if (!cfg) {
              throw new Error(
                "deepsec sandbox: no deepsec.config.ts found above cwd. Sandbox needs a deepsec workspace (run `deepsec init` first).",
              );
            }
            return { root: path.dirname(cfg), mode: "installed" };
          }
          // Dev: walk up from the package to the workspace root.
          let wsDir = path.dirname(dir);
          while (wsDir !== path.dirname(wsDir)) {
            if (fs.existsSync(path.join(wsDir, "pnpm-workspace.yaml"))) {
              return { root: wsDir, mode: "dev" };
            }
            wsDir = path.dirname(wsDir);
          }
          // Source package without a monorepo above — uncommon, but treat
          // as installed (one-package install in the sandbox).
          return { root: dir, mode: "installed" };
        }
      } catch {
        // Unreadable / non-JSON package.json — keep walking.
      }
    }
    dir = path.dirname(dir);
  }
  throw new Error(
    "Could not locate the deepsec package directory (no package.json with name 'deepsec' found in any ancestor)",
  );
}

async function prepareUploads(
  config: SandboxConfig,
  mode: DeepsecMode,
  appRoot: string,
  onLog: (msg: string) => void,
): Promise<UploadBundle> {
  const project = readProjectConfig(config.projectId);
  const localTargetRoot = project.rootPath;
  const localDataDir = dataDir(config.projectId);

  onLog(
    `Preparing upload bundles (mode=${mode}, app=${appRoot}, target=${localTargetRoot}, data=${localDataDir})...`,
  );

  const [app, target, data] = await Promise.all([
    makeTarball(appRoot, DEEPSEC_APP_EXCLUDES, onLog),
    makeTarball(localTargetRoot, TARGET_EXCLUDES, onLog),
    makeTarball(localDataDir, DATA_EXCLUDES, onLog),
  ]);

  return { app, target, data };
}

// --- Partition + bootstrap + spawn N workers ---

interface BootstrapAndSpawnResult {
  instances: SandboxInstance[];
  partitions: string[][];
  totalFiles: number;
  snapshotId: string | null;
  mode: DeepsecMode;
}

async function bootstrapAndSpawn(
  config: SandboxConfig,
  onLog: (msg: string) => void,
): Promise<BootstrapAndSpawnResult> {
  const ctx = resolveDeepsecAppContext();
  const usePartitioning = PARTITIONABLE_COMMANDS.has(config.command);
  let partitions: string[][];
  let totalFiles: number;

  if (usePartitioning) {
    onLog("Partitioning files across sandboxes...");
    const result = partitionFiles(config.projectId, config.sandboxCount, {
      command: config.command,
      limit: config.limit,
      filter: config.filter,
      reinvestigate: config.reinvestigate,
      force: config.force,
      minSeverity: config.minSeverity,
      agentType: config.agentType,
    });
    partitions = result.partitions;
    totalFiles = result.totalFiles;

    if (totalFiles === 0) {
      onLog("No files to process.");
      return { instances: [], partitions: [], totalFiles: 0, snapshotId: null, mode: ctx.mode };
    }

    onLog(
      `${totalFiles} files partitioned across ${partitions.length} sandbox(es): ${partitions.map((p) => p.length).join(", ")} files each`,
    );
  } else {
    if (config.sandboxCount > 1) {
      onLog(`Warning: '${config.command}' doesn't support file partitioning. Using 1 sandbox.`);
    }
    partitions = [[]];
    totalFiles = 0;
    onLog(`Running '${config.command}' on 1 sandbox...`);
  }

  // Step 1: get a snapshot — either use one the user passed, or build a fresh one
  let snapshotId = config.snapshotId ?? null;
  if (!snapshotId) {
    const bundle = await prepareUploads(config, ctx.mode, ctx.root, onLog);
    snapshotId = await createBootstrapSnapshot({
      projectId: config.projectId,
      agentType: config.agentType,
      vcpus: config.vcpus,
      timeout: config.timeout,
      mode: ctx.mode,
      bundle,
      onLog,
    });
  } else {
    onLog(`Using provided snapshot: ${snapshotId}`);
  }

  // Step 2: spawn N worker sandboxes from the snapshot in parallel
  onLog(`Spawning ${partitions.length} worker sandbox(es) from snapshot ${snapshotId}...`);

  const spawnPromises = partitions.map(async (partition, idx): Promise<SandboxInstance> => {
    try {
      const sandbox = await spawnFromSnapshot({
        snapshotId: snapshotId!,
        agentType: config.agentType,
        vcpus: config.vcpus,
        timeout: config.timeout,
        mode: ctx.mode,
        allowedHosts: config.allowedHosts,
        onLog: (msg) => onLog(`[sandbox-${idx}] ${msg}`),
      });
      onLog(`[sandbox-${idx}] Ready (${sandbox.sandboxId}, ${partition.length} files)`);
      return {
        sandbox,
        index: idx,
        sandboxId: sandbox.sandboxId,
        status: "setup",
        manifest: partition,
      };
    } catch (err: any) {
      const parts: string[] = [];
      if (err?.message) parts.push(err.message);
      if (err?.status) parts.push(`status: ${err.status}`);
      if (err?.body) parts.push(`body: ${JSON.stringify(err.body).slice(0, 300)}`);
      if (err?.response?.status) parts.push(`response.status: ${err.response.status}`);
      if (err?.cause) parts.push(`cause: ${err.cause}`);
      const errMsg = parts.join(" | ") || String(err);
      onLog(`[sandbox-${idx}] Spawn failed: ${errMsg}`);
      return {
        sandbox: null as unknown as Sandbox,
        index: idx,
        sandboxId: "",
        status: "error" as const,
        manifest: partition,
        error: errMsg,
      } satisfies SandboxInstance;
    }
  });

  const instances = await Promise.all(spawnPromises);
  return { instances, partitions, totalFiles, snapshotId, mode: ctx.mode };
}

// --- Dispatch: kick off command on a sandbox, return cmdId ---

async function dispatchOnSandbox(
  instance: SandboxInstance,
  config: SandboxConfig,
  mode: DeepsecMode,
  onLog: (msg: string) => void,
): Promise<string | null> {
  if (instance.status === "error") return null;

  const { sandbox, index, manifest } = instance;

  let manifestPath: string | null = null;
  if (PARTITIONABLE_COMMANDS.has(config.command) && manifest.length > 0) {
    manifestPath = "/tmp/manifest.json";
    await sandbox.writeFiles([
      { path: manifestPath, content: Buffer.from(JSON.stringify(manifest)) },
    ]);
  }

  const invocation = buildSandboxInvocation(config, mode, manifestPath);
  onLog(
    `[sandbox-${index}] Dispatching: deepsec ${config.command} (${manifest.length || "all"} files)...`,
  );

  const cmd = await sandbox.runCommand({
    cmd: invocation.cmd,
    args: invocation.args,
    cwd: DEEPSEC_DIR,
    detached: true,
  });

  return cmd.cmdId;
}

// --- Launch (detached) ---

export async function launch(config: SandboxConfig, onLog: (msg: string) => void): Promise<string> {
  const {
    instances,
    partitions: _p,
    totalFiles: _t,
    mode,
  } = await bootstrapAndSpawn(config, onLog);

  if (instances.length === 0) {
    throw new Error("No sandboxes to launch (no files to process?)");
  }

  const runId = generateRunId();
  onLog(`Run ${runId}: dispatching commands...`);

  const sandboxEntries: SandboxRunState["sandboxes"] = [];

  for (const inst of instances) {
    const cmdId = await dispatchOnSandbox(inst, config, mode, onLog);
    if (cmdId) {
      sandboxEntries.push({
        sandboxId: inst.sandboxId,
        cmdId,
        index: inst.index,
        manifest: inst.manifest,
      });
    }
  }

  const state: SandboxRunState = {
    runId,
    projectId: config.projectId,
    command: config.command,
    vcpus: config.vcpus,
    launchedAt: new Date().toISOString(),
    sandboxes: sandboxEntries,
  };

  saveRunState(state);
  onLog(`Run ${runId} launched with ${sandboxEntries.length} sandbox(es). You can disconnect now.`);
  onLog(
    `  Collect results later: pnpm deepsec sandbox collect --project-id ${config.projectId} --run-id ${runId}`,
  );
  onLog(
    `  Check status:          pnpm deepsec sandbox status --project-id ${config.projectId} --run-id ${runId}`,
  );

  return runId;
}

// --- Status: check on a detached run ---

export async function checkStatus(
  projectId: string,
  runId?: string,
  onLog: (msg: string) => void = console.log,
): Promise<void> {
  if (!runId) {
    const runs = listRunStates(projectId);
    if (runs.length === 0) {
      onLog("No detached sandbox runs found.");
      return;
    }
    onLog(`Detached sandbox runs for ${projectId}:`);
    for (const run of runs) {
      onLog(
        `  ${run.runId}  ${run.command}  ${run.sandboxes.length} sandbox(es)  launched ${run.launchedAt}`,
      );
    }
    return;
  }

  const state = loadRunState(projectId, runId);
  onLog(`Run ${runId}: ${state.command} (launched ${state.launchedAt})`);

  for (const entry of state.sandboxes) {
    try {
      const sandbox = await Sandbox.get({ sandboxId: entry.sandboxId });
      const cmd = await sandbox.getCommand(entry.cmdId);

      if (cmd.exitCode === null) {
        onLog(
          `  sandbox-${entry.index} (${entry.sandboxId}): RUNNING (${entry.manifest.length} files)`,
        );
      } else if (cmd.exitCode === 0) {
        onLog(
          `  sandbox-${entry.index} (${entry.sandboxId}): COMPLETE (exit 0, ${entry.manifest.length} files)`,
        );
      } else {
        onLog(`  sandbox-${entry.index} (${entry.sandboxId}): FAILED (exit ${cmd.exitCode})`);
      }
    } catch (err) {
      onLog(
        `  sandbox-${entry.index} (${entry.sandboxId}): UNREACHABLE (${err instanceof Error ? err.message : err})`,
      );
    }
  }
}

// --- Collect: reconnect to completed sandboxes, pull results, stop ---

export async function collect(
  projectId: string,
  runId: string,
  onLog: (msg: string) => void,
): Promise<SandboxResult[]> {
  const state = loadRunState(projectId, runId);
  onLog(`Collecting run ${runId}: ${state.command} (${state.sandboxes.length} sandboxes)`);

  const resultPromises = state.sandboxes.map(async (entry): Promise<SandboxResult> => {
    try {
      const sandbox = await Sandbox.get({ sandboxId: entry.sandboxId });
      const cmd = await sandbox.getCommand(entry.cmdId);

      if (cmd.exitCode === null) {
        onLog(`[sandbox-${entry.index}] Still running, waiting...`);
        try {
          for await (const log of cmd.logs()) {
            const lines = log.data.trim();
            if (lines) {
              for (const line of lines.split("\n")) {
                onLog(`[sandbox-${entry.index}] ${line}`);
              }
            }
          }
        } catch {}
        const finished = await cmd.wait();
        if (finished.exitCode !== 0) {
          const stderr = await finished.stderr();
          onLog(`[sandbox-${entry.index}] Failed (exit ${finished.exitCode})`);
          try {
            await sandbox.stop();
          } catch {}
          return {
            sandboxIndex: entry.index,
            sandboxId: entry.sandboxId,
            success: false,
            filesProcessed: 0,
            error: `Exit ${finished.exitCode}: ${stderr.slice(0, 500)}`,
          };
        }
      } else if (cmd.exitCode !== 0) {
        const stderr = await cmd.stderr();
        onLog(`[sandbox-${entry.index}] Was failed (exit ${cmd.exitCode})`);
        try {
          await sandbox.stop();
        } catch {}
        return {
          sandboxIndex: entry.index,
          sandboxId: entry.sandboxId,
          success: false,
          filesProcessed: 0,
          error: `Exit ${cmd.exitCode}: ${stderr.slice(0, 500)}`,
        };
      }

      onLog(`[sandbox-${entry.index}] Complete, downloading results...`);
      try {
        await downloadResults(sandbox, entry.index, projectId, onLog);
      } catch (err) {
        onLog(
          `[sandbox-${entry.index}] Download failed: ${err instanceof Error ? err.message : err}`,
        );
      }

      try {
        await sandbox.stop();
      } catch {}
      untrackSandbox(sandbox);
      onLog(`[sandbox-${entry.index}] Stopped.`);

      return {
        sandboxIndex: entry.index,
        sandboxId: entry.sandboxId,
        success: true,
        filesProcessed: entry.manifest.length,
      };
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err);
      onLog(`[sandbox-${entry.index}] Unreachable: ${errMsg}`);
      return {
        sandboxIndex: entry.index,
        sandboxId: entry.sandboxId,
        success: false,
        filesProcessed: 0,
        error: errMsg,
      };
    }
  });

  const results = await Promise.all(resultPromises);

  deleteRunState(projectId, runId);
  onLog(`Run ${runId} collected and cleaned up.`);

  return results;
}

// --- Orchestrate (attached): bootstrap → spawn → run → download → stop ---

export async function orchestrate(
  config: SandboxConfig,
  onLog: (msg: string) => void,
): Promise<SandboxResult[]> {
  const { instances, mode } = await bootstrapAndSpawn(config, onLog);

  if (instances.length === 0) return [];

  onLog(`Dispatching '${config.command}' commands...`);

  const runPromises = instances.map(async (inst) => {
    // Start a background poller that streams deltas from the sandbox while
    // the worker runs. A nudge lets runOnSandboxAttached kick the poller as
    // soon as it sees "Batch N/M complete:" in the log.
    const stopPoller = { flag: false };
    const nudge = makeNudge();
    const pollerPromise =
      inst.status === "error"
        ? Promise.resolve()
        : streamDownloadLoop(inst, config.projectId, onLog, stopPoller, nudge);

    const result = await runOnSandboxAttached(inst, config, mode, onLog, nudge);
    const tRun = Date.now();

    // Stop the poller and wait for it to wind down (it may be mid-download).
    // Signal the nudge so any in-flight `nudge.wait(15_000)` wakes immediately
    // instead of sleeping the full interval before checking stop.flag.
    stopPoller.flag = true;
    nudge.signal();
    await pollerPromise;
    const tPoller = Date.now();
    if (tPoller - tRun > 500) {
      onLog(`[sandbox-${inst.index}] [debug] pollerPromise wind-down took ${tPoller - tRun}ms`);
    }

    // One final sync to catch whatever the poller may have missed between
    // its last iteration and the worker exiting.
    if (inst.status !== "error") {
      try {
        await downloadResults(inst.sandbox, inst.index, config.projectId, onLog);
      } catch (err) {
        onLog(
          `[sandbox-${inst.index}] Final download failed: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }
    const tDownload = Date.now();
    if (tDownload - tPoller > 500) {
      onLog(`[sandbox-${inst.index}] [debug] final downloadResults took ${tDownload - tPoller}ms`);
    }

    // Stop the sandbox immediately — no reason to keep it around.
    if (!config.keepAlive && inst.sandboxId) {
      try {
        await inst.sandbox.stop();
        onLog(`[sandbox-${inst.index}] Stopped.`);
      } catch {}
      untrackSandbox(inst.sandbox);
    }
    const tStop = Date.now();
    if (tStop - tDownload > 500) {
      onLog(`[sandbox-${inst.index}] [debug] sandbox.stop() took ${tStop - tDownload}ms`);
    }

    return result;
  });

  const runResults = await Promise.all(runPromises);

  if (config.keepAlive) {
    onLog("Sandboxes kept alive:");
    for (const inst of instances) {
      if (inst.sandboxId) {
        onLog(`  sandbox-${inst.index}: ${inst.sandboxId}`);
      }
    }
  }

  return runResults;
}

/**
 * Simple signal channel: the log-stream parser calls `signal()` when it
 * sees a "Batch N/M complete:" line; the streaming loop waits on `wait()`
 * (or its interval timer, whichever fires first).
 */
interface SyncNudge {
  signal: () => void;
  wait: (timeoutMs: number) => Promise<void>;
}

function makeNudge(): SyncNudge {
  let resolver: (() => void) | null = null;
  return {
    signal() {
      if (resolver) {
        const r = resolver;
        resolver = null;
        r();
      }
    },
    wait(timeoutMs: number) {
      return new Promise<void>((resolve) => {
        const timer = setTimeout(() => {
          resolver = null;
          resolve();
        }, timeoutMs);
        resolver = () => {
          clearTimeout(timer);
          resolve();
        };
      });
    },
  };
}

/**
 * Periodically sync files changed since the last sync. Triggered by either
 * a batch-complete nudge from the log parser or a 15s timer (safety net).
 * Runs until `stop.flag` becomes true.
 */
async function streamDownloadLoop(
  inst: SandboxInstance,
  projectId: string,
  onLog: (msg: string) => void,
  stop: { flag: boolean },
  nudge: SyncNudge,
  intervalMs = 15_000,
): Promise<void> {
  // Small initial delay so the worker has time to make progress.
  await nudge.wait(intervalMs);
  while (!stop.flag) {
    const tStart = Date.now();
    try {
      const count = await downloadResults(inst.sandbox, inst.index, projectId, onLog, {
        advanceMarker: true,
        quiet: true,
      });
      const dt = Date.now() - tStart;
      if (count > 0) onLog(`[sandbox-${inst.index}] streamed ${count} file(s) in ${dt}ms`);
      else if (dt > 1500)
        onLog(`[sandbox-${inst.index}] [debug] silent poller sync took ${dt}ms (0 files)`);
    } catch (err) {
      onLog(
        `[sandbox-${inst.index}] periodic sync: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    if (stop.flag) break;
    await nudge.wait(intervalMs);
  }
}

const BATCH_COMPLETE_RE = /Batch \d+\/\d+ complete:/;

async function runOnSandboxAttached(
  instance: SandboxInstance,
  config: SandboxConfig,
  mode: DeepsecMode,
  onLog: (msg: string) => void,
  nudge?: SyncNudge,
): Promise<SandboxResult> {
  if (instance.status === "error") {
    return {
      sandboxIndex: instance.index,
      sandboxId: instance.sandboxId,
      success: false,
      filesProcessed: 0,
      error: instance.error,
    };
  }

  const { sandbox, index, manifest } = instance;
  instance.status = "running";

  try {
    let manifestPath: string | null = null;
    if (PARTITIONABLE_COMMANDS.has(config.command) && manifest.length > 0) {
      manifestPath = "/tmp/manifest.json";
      await sandbox.writeFiles([
        { path: manifestPath, content: Buffer.from(JSON.stringify(manifest)) },
      ]);
    }

    const invocation = buildSandboxInvocation(config, mode, manifestPath);
    onLog(
      `[sandbox-${index}] Running: deepsec ${config.command} (${manifest.length || "all"} files)...`,
    );

    const cmd = await sandbox.runCommand({
      cmd: invocation.cmd,
      args: invocation.args,
      cwd: DEEPSEC_DIR,
      detached: true,
    });

    try {
      for await (const log of cmd.logs()) {
        const lines = log.data.trim();
        if (lines) {
          for (const line of lines.split("\n")) {
            onLog(`[sandbox-${index}] ${line}`);
            if (nudge && BATCH_COMPLETE_RE.test(line)) {
              // Kick the streaming download loop to sync now — a batch
              // just finished and wrote file records to disk.
              nudge.signal();
            }
          }
        }
      }
    } catch {}
    const tLogsClosed = Date.now();

    const result = await cmd.wait();
    const tWaitReturned = Date.now();
    const waitGap = tWaitReturned - tLogsClosed;
    if (waitGap > 500) {
      onLog(`[sandbox-${index}] [debug] cmd.wait() lagged ${waitGap}ms after cmd.logs() closed`);
    }

    if (result.exitCode !== 0) {
      const stderr = await result.stderr();
      instance.status = "error";
      instance.error = `Exit code ${result.exitCode}: ${stderr.slice(0, 500)}`;
      onLog(`[sandbox-${index}] ${config.command} failed (exit ${result.exitCode})`);
      return {
        sandboxIndex: index,
        sandboxId: sandbox.sandboxId,
        success: false,
        filesProcessed: 0,
        error: instance.error,
      };
    }

    instance.status = "done";
    onLog(`[sandbox-${index}] ${config.command} complete.`);
    return {
      sandboxIndex: index,
      sandboxId: sandbox.sandboxId,
      success: true,
      filesProcessed: manifest.length,
    };
  } catch (err) {
    const errMsg = err instanceof Error ? err.message : String(err);
    instance.status = "error";
    instance.error = errMsg;
    onLog(`[sandbox-${index}] Error: ${errMsg}`);
    return {
      sandboxIndex: index,
      sandboxId: sandbox.sandboxId,
      success: false,
      filesProcessed: 0,
      error: errMsg,
    };
  }
}

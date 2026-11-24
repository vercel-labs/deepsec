import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  dataDir,
  generateRunId as generateWorkerRunId,
  getConfigPath,
  getDataRoot,
  readFileRecord,
  readProjectConfig,
  writeFileRecord,
} from "@deepsec/core";
import { Sandbox } from "@vercel/sandbox";
import { downloadResults } from "./download.js";
import { hasLiveLock, partitionFiles } from "./partitioner.js";
import {
  createBootstrapSnapshot,
  DEEPSEC_DIR,
  type DeepsecMode,
  spawnFromSnapshot,
  TARGET_DIR,
  type UploadBundle,
} from "./setup.js";
import { addShutdownCleanup, untrackSandbox } from "./shutdown.js";
import {
  deleteRunState,
  generateRunId,
  listRunStates,
  loadRunState,
  saveRunState,
  updateRunState,
} from "./state.js";
import type {
  SandboxConfig,
  SandboxInstance,
  SandboxResult,
  SandboxRunState,
  SpawnLimiter,
} from "./types.js";
import {
  DATA_EXCLUDES,
  DEEPSEC_APP_EXCLUDES,
  makeTarball,
  nestedExcludePaths,
  TARGET_EXCLUDES,
} from "./upload.js";

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
  workerRunId?: string,
): { cmd: string; args: string[] } {
  const base = buildDeepsecInvocation(config, mode, manifestPath);
  // `process` workers create their run with this ID, so their file locks
  // can be told apart from other runs'. env(1) adds the variable without
  // replacing the sandbox's environment.
  if (!workerRunId || config.command !== "process") return base;
  return { cmd: "env", args: [`DEEPSEC_WORKER_RUN_ID=${workerRunId}`, base.cmd, ...base.args] };
}

function buildDeepsecInvocation(
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

// An agent inside a sandbox can emit pathological output volume (e.g.
// `rg '^'` over a large repo). The log stream is parsed record-by-record
// with unbounded JSON.parse inside @vercel/sandbox, so without a cap it
// can OOM this orchestrator process. Budget is per command stream.
const MAX_LOG_BYTES_PER_SANDBOX = 10 * 1024 * 1024;
const MAX_LOG_LINE_CHARS = 2_000;

/**
 * Stream a command's logs through onLog with a byte budget and per-line
 * truncation. Once the budget is exhausted the stream is aborted; the
 * caller's cmd.wait() remains the arbiter of completion. Never throws.
 *
 * onRawLine receives each untruncated line (used for batch-complete
 * detection) before display truncation is applied.
 */
type LoggableCommand = {
  logs(opts?: { signal?: AbortSignal }): AsyncIterable<{ stream?: string; data: string }>;
};

// Memory-pressure backstop for the log streams. The SDK's internal pipe()
// ignores write() backpressure, so a burst producer can buffer log data
// inside the SDK faster than our consumed-byte caps drain it. That backlog
// lives mostly in Buffers (external memory, NOT heapUsed), so the trigger
// must sum heapUsed + external. On pressure, abort every live stream: the
// abort propagates into the SDK and frees the backlog; cmd.wait() remains
// the arbiter of command completion.
const MEMORY_PRESSURE_ABORT_BYTES = 3 * 1024 * 1024 * 1024;
const activeLogAborters = new Set<AbortController>();
let memoryWatchdog: NodeJS.Timeout | undefined;

function registerLogAborter(aborter: AbortController): void {
  activeLogAborters.add(aborter);
  if (!memoryWatchdog) {
    memoryWatchdog = setInterval(() => {
      const m = process.memoryUsage();
      if (m.heapUsed + m.external > MEMORY_PRESSURE_ABORT_BYTES) {
        for (const ctl of activeLogAborters) {
          ctl.abort(new Error("memory pressure"));
        }
        activeLogAborters.clear();
      }
    }, 1000);
    memoryWatchdog.unref();
  }
}

function unregisterLogAborter(aborter: AbortController): void {
  activeLogAborters.delete(aborter);
  if (activeLogAborters.size === 0 && memoryWatchdog) {
    clearInterval(memoryWatchdog);
    memoryWatchdog = undefined;
  }
}

// The Sandbox API sometimes closes a command's log stream long before the
// command exits. Each reconnect replays the log from the start, so already
// shown lines are skipped by count.
const MAX_LOG_RECONNECTS = 100;
// The display budget above only counts lines that are shown, so replays
// don't use it up. Raw bytes received, replays included, get their own
// fixed budget, charged before any concatenation, so a worker can't make
// the host buffer or rescan unbounded output.
const MAX_LOG_INCOMING_BYTES_PER_SANDBOX = 4 * MAX_LOG_BYTES_PER_SANDBOX;
// Longest unterminated line kept while waiting for its newline; the rest of
// that line is dropped. Line counting only depends on newlines, so replay
// deduplication is unaffected.
const MAX_LOG_PARTIAL_CHARS = 64 * 1024;

export async function streamLogsCapped(
  cmd: LoggableCommand,
  prefix: string,
  onLog: (msg: string) => void,
  onRawLine?: (line: string) => void,
  isFinished?: () => Promise<boolean>,
): Promise<void> {
  const aborter = new AbortController();
  registerLogAborter(aborter);
  let remaining = MAX_LOG_BYTES_PER_SANDBOX;
  let incoming = 0;
  let emitted = 0;
  let exhausted = false;
  const emit = (line: string) => {
    remaining -= Buffer.byteLength(line) + 1;
    onRawLine?.(line);
    const shown =
      line.length > MAX_LOG_LINE_CHARS
        ? `${line.slice(0, MAX_LOG_LINE_CHARS)}… [line truncated]`
        : line;
    onLog(`${prefix} ${shown}`);
  };
  try {
    for (let attempt = 0; attempt <= MAX_LOG_RECONNECTS; attempt++) {
      let index = 0;
      let partial = "";
      try {
        for await (const log of cmd.logs({ signal: aborter.signal })) {
          incoming += Buffer.byteLength(log.data);
          if (incoming > MAX_LOG_INCOMING_BYTES_PER_SANDBOX) {
            exhausted = true;
            onLog(
              `${prefix} [log stream exceeded ${Math.round(MAX_LOG_INCOMING_BYTES_PER_SANDBOX / 1024 / 1024)}MiB including replays after reconnects; further output suppressed]`,
            );
            aborter.abort();
            break;
          }
          const parts = (partial + log.data).split("\n");
          partial = parts.pop() ?? "";
          if (partial.length > MAX_LOG_PARTIAL_CHARS)
            partial = partial.slice(0, MAX_LOG_PARTIAL_CHARS);
          for (const line of parts) {
            if (index++ < emitted) continue;
            emitted++;
            if (line.trim()) emit(line);
          }
          if (remaining <= 0) {
            exhausted = true;
            onLog(
              `${prefix} [log stream exceeded ${Math.round(MAX_LOG_BYTES_PER_SANDBOX / 1024 / 1024)}MiB; further output suppressed]`,
            );
            aborter.abort();
            break;
          }
        }
      } catch {
        // Stream errors (including our own abort) are non-fatal here.
      }
      const done =
        aborter.signal.aborted ||
        exhausted ||
        !isFinished ||
        attempt === MAX_LOG_RECONNECTS ||
        (await isFinished());
      if (done) {
        if (partial.trim() && index++ >= emitted) {
          emitted++;
          emit(partial);
        }
        break;
      }
      // The replay after reconnecting delivers this unterminated line again,
      // complete, so it isn't emitted (or counted) here.
      if (attempt === 0) onLog(`${prefix} [log stream closed early; reconnecting]`);
    }
  } finally {
    unregisterLogAborter(aborter);
  }
  if (aborter.signal.aborted && !exhausted) {
    onLog(`${prefix} [log stream aborted under memory pressure; further output suppressed]`);
  }
}

/**
 * Read a command's stderr via the log stream, aborting once maxChars have
 * been collected. cmd.stderr() accumulates the entire stream into memory
 * with no cap, so it must not be called on agent-driven commands.
 */
async function readStderrCapped(cmd: LoggableCommand, maxChars: number): Promise<string> {
  const aborter = new AbortController();
  registerLogAborter(aborter);
  let out = "";
  try {
    for await (const log of cmd.logs({ signal: aborter.signal })) {
      if (log.stream !== "stderr") continue;
      out += log.data;
      if (out.length >= maxChars) {
        aborter.abort();
        break;
      }
    }
  } catch {
    // Stream errors (including our own abort) are non-fatal here.
  } finally {
    unregisterLogAborter(aborter);
  }
  return out.slice(0, maxChars);
}

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

  // `deepsec init` places the workspace inside the target by default. Keep it
  // (credentials, data mirror) out of the target bundle in git and non-git mode.
  const configPath = getConfigPath();
  const targetExcludePaths = nestedExcludePaths(localTargetRoot, [
    ...(configPath ? [path.dirname(configPath)] : []),
    getDataRoot(),
  ]);

  const [app, target, data] = await Promise.all([
    makeTarball(appRoot, DEEPSEC_APP_EXCLUDES, onLog),
    makeTarball(localTargetRoot, TARGET_EXCLUDES, onLog, { excludePaths: targetExcludePaths }),
    makeTarball(localDataDir, DATA_EXCLUDES, onLog),
  ]);

  return { app, target, data };
}

// --- Partition + bootstrap + spawn N workers ---

interface BootstrapAndSpawnResult {
  /** One promise per partition, resolving when that sandbox is ready (or failed). */
  spawns: Promise<SandboxInstance>[];
  partitions: string[][];
  totalFiles: number;
  snapshotId: string | null;
  mode: DeepsecMode;
}

const PARTITION_LOCK_STALE_MS = 2 * 60 * 1000;
const PARTITION_LOCK_WAIT_MS = 5 * 60 * 1000;

/**
 * Run `fn` while holding `sandbox-runs/.partition.lock` (created with
 * O_EXCL). A lock older than PARTITION_LOCK_STALE_MS is treated as left
 * behind by a crashed process; partitioning itself takes seconds.
 */
export async function withPartitionLock<T>(projectId: string, fn: () => T): Promise<T> {
  const dir = path.join(dataDir(projectId), "sandbox-runs");
  fs.mkdirSync(dir, { recursive: true });
  const lock = path.join(dir, ".partition.lock");
  const deadline = Date.now() + PARTITION_LOCK_WAIT_MS;
  for (;;) {
    try {
      fs.closeSync(fs.openSync(lock, "wx"));
      break;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      try {
        if (Date.now() - fs.statSync(lock).mtimeMs > PARTITION_LOCK_STALE_MS) {
          fs.unlinkSync(lock);
          continue;
        }
      } catch {
        continue; // the holder released it between our calls
      }
      if (Date.now() > deadline) throw new Error(`Timed out waiting for ${lock}`);
      await new Promise((r) => setTimeout(r, 250));
    }
  }
  try {
    return fn();
  } finally {
    try {
      fs.unlinkSync(lock);
    } catch {}
  }
}

async function bootstrapAndSpawn(
  config: SandboxConfig,
  onLog: (msg: string) => void,
  onPartitioned?: (partitions: string[][]) => void,
): Promise<BootstrapAndSpawnResult> {
  const ctx = resolveDeepsecAppContext();
  const usePartitioning = PARTITIONABLE_COMMANDS.has(config.command);
  let partitions: string[][];
  let totalFiles: number;

  if (usePartitioning) {
    onLog("Partitioning files across sandboxes...");
    // Partition and reserve under one lock, so two runs starting at the same
    // time can't both select the same files before either has reserved them.
    const result = await withPartitionLock(config.projectId, () => {
      const r = partitionFiles(config.projectId, config.sandboxCount, {
        command: config.command,
        limit: config.limit,
        filter: config.filter,
        reinvestigate: config.reinvestigate,
        force: config.force,
        minSeverity: config.minSeverity,
        agentType: config.agentType,
      });
      // Reserve the files before the (slow) snapshot build, so a concurrent
      // run can't partition them while this one bootstraps or ramps up.
      if (r.totalFiles > 0) onPartitioned?.(r.partitions);
      return r;
    });
    partitions = result.partitions;
    totalFiles = result.totalFiles;

    if (totalFiles === 0) {
      onLog("No files to process.");
      return { spawns: [], partitions: [], totalFiles: 0, snapshotId: null, mode: ctx.mode };
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
    try {
      snapshotId = await createBootstrapSnapshot({
        projectId: config.projectId,
        agentType: config.agentType,
        vcpus: config.vcpus,
        timeout: config.timeout,
        mode: ctx.mode,
        bundle,
        onLog,
      });
    } finally {
      // Belt-and-suspenders: uploadTarballToSandbox unlinks each tarball on
      // success, but if snapshot creation throws before all three uploads
      // have run we'd leak the rest in os.tmpdir(). Best-effort sweep so
      // long-running orchestrators don't accumulate stale temp files.
      for (const t of [bundle.app.tarPath, bundle.target.tarPath, bundle.data.tarPath]) {
        try {
          fs.unlinkSync(t);
        } catch {}
      }
    }
  } else {
    onLog(`Using provided snapshot: ${snapshotId}`);
  }

  // Step 2: spawn N worker sandboxes from the snapshot, staggered so a big
  // run doesn't hit the Sandbox API and the model provider all at once.
  const limiter = config.spawnLimiter;
  const delays = limiter ? [] : spawnDelays(partitions.length, config.spawnRate);
  const ramp = Math.max(0, ...delays);
  onLog(
    `Spawning ${partitions.length} worker sandbox(es) from snapshot ${snapshotId}` +
      (limiter
        ? ` at up to ${config.spawnRate}/min shared with the other projects...`
        : ramp > 0
          ? ` at up to ${config.spawnRate}/min (over ~${Math.ceil(ramp / 60_000)} min)...`
          : "..."),
  );

  const spawns = partitions.map(async (partition, idx): Promise<SandboxInstance> => {
    const workerRunId = generateWorkerRunId();
    // Claim the limiter slot synchronously, in partition order.
    const slot = limiter?.next();
    try {
      if (slot) await slot;
      else if (delays[idx] > 0) await new Promise((r) => setTimeout(r, delays[idx]));
      const sandbox = await spawnFromSnapshot({
        snapshotId: snapshotId!,
        agentType: config.agentType,
        aiApiKeyEnv: config.aiApiKeyEnv,
        aiBaseUrl: config.aiBaseUrl,
        brokeredModelCredential: config.brokeredModelCredential,
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
        workerRunId,
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

  return { spawns, partitions, totalFiles, snapshotId, mode: ctx.mode };
}

/**
 * Start offsets (ms) for `count` sandboxes at up to `perMinute` per minute:
 * sandbox i gets slot i of width 60s/perMinute and a random point inside
 * it, so any 60s window sees at most perMinute + 1 starts. Runs no larger
 * than one minute's budget start at once.
 */
export function spawnDelays(
  count: number,
  perMinute?: number,
  random: () => number = Math.random,
): number[] {
  if (!perMinute || perMinute <= 0 || count <= perMinute) return new Array(count).fill(0);
  const slot = 60_000 / perMinute;
  return Array.from({ length: count }, (_, i) => Math.floor(i * slot + random() * slot));
}

/**
 * A spawn schedule shared by several orchestrations (`sandbox-all` runs one
 * per project). Each `next()` takes the next free slot of width
 * 60s/perMinute, never earlier than now, and resolves at a random point in
 * it, so any 60s window sees at most perMinute + 1 starts across all callers.
 */
export function createSpawnLimiter(
  perMinute: number,
  random: () => number = Math.random,
  now: () => number = Date.now,
): SpawnLimiter {
  const slot = 60_000 / perMinute;
  let nextFree = 0;
  return {
    async next() {
      const t = now();
      nextFree = Math.max(nextFree, t);
      const at = nextFree + random() * slot;
      nextFree += slot;
      if (at > t) await new Promise((r) => setTimeout(r, at - t));
    },
  };
}

/**
 * Tracks a run's saved state from partitioning onward: planned partitions
 * are reserved first, move to `sandboxes` when dispatched, and leave once
 * nothing is left to collect. The file is deleted when both lists are empty.
 */
function createRunStateTracker(config: SandboxConfig, runId: string, onLog: (msg: string) => void) {
  const state: SandboxRunState = {
    runId,
    projectId: config.projectId,
    command: config.command,
    vcpus: config.vcpus,
    launchedAt: new Date().toISOString(),
    sandboxes: [],
    reserved: [],
  };
  let saved = false;
  let announced = false;
  const write = () => {
    try {
      if (state.sandboxes.length === 0 && (state.reserved?.length ?? 0) === 0) {
        if (saved) deleteRunState(config.projectId, runId);
        saved = false;
        return;
      }
      if (saved) updateRunState(state);
      else {
        saveRunState(state);
        saved = true;
      }
    } catch (err) {
      onLog(`Could not save run state: ${err instanceof Error ? err.message : String(err)}`);
    }
  };
  const unreserve = (index: number) => {
    state.reserved = (state.reserved ?? []).filter((r) => r.index !== index);
  };
  return {
    state,
    reserve(partitions: string[][]) {
      state.reserved = partitions.map((manifest, index) => ({ index, manifest }));
      write();
    },
    dispatched(inst: SandboxInstance) {
      if (!inst.cmdId) return;
      unreserve(inst.index);
      state.sandboxes.push({
        sandboxId: inst.sandboxId,
        cmdId: inst.cmdId,
        index: inst.index,
        manifest: inst.manifest,
        workerRunId: inst.workerRunId,
        dispatchedAt: new Date().toISOString(),
      });
      write();
      if (!announced && saved) {
        announced = true;
        onLog(
          `Run state ${runId} saved. If this process stops, recover with: pnpm deepsec sandbox collect --project-id ${config.projectId} --run-id ${runId}`,
        );
      }
    },
    /** A partition that will never be dispatched (spawn or dispatch failed). */
    abandon(index: number) {
      unreserve(index);
      write();
    },
    /** A dispatched worker with nothing left to collect. */
    drop(index: number) {
      state.sandboxes = state.sandboxes.filter((e) => e.index !== index);
      write();
    },
    /**
     * Give back partitions that won't be dispatched: bootstrap failed or
     * the CLI is shutting down. Dispatched workers stay, so `collect` can
     * still reach them or release their files.
     */
    release() {
      if ((state.reserved?.length ?? 0) === 0) return;
      state.reserved = [];
      write();
    },
  };
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

  const invocation = buildSandboxInvocation(config, mode, manifestPath, instance.workerRunId);
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
  const runId = generateRunId();
  const tracker = createRunStateTracker(config, runId, onLog);
  const removeCleanup = addShutdownCleanup(() => tracker.release());
  try {
    const { spawns, mode } = await bootstrapAndSpawn(config, onLog, (partitions) =>
      tracker.reserve(partitions),
    );
    if (spawns.length === 0) {
      throw new Error("No sandboxes to launch (no files to process?)");
    }
    onLog(`Run ${runId}: dispatching commands as sandboxes become ready...`);
    // Each worker is dispatched and saved as soon as its sandbox is ready,
    // so a crash during a staggered ramp still leaves every started worker
    // recoverable by `collect`.
    await Promise.all(
      spawns.map(async (spawn) => {
        const inst = await spawn;
        let cmdId: string | null = null;
        try {
          cmdId = await dispatchOnSandbox(inst, config, mode, onLog);
        } catch (err) {
          onLog(
            `[sandbox-${inst.index}] Dispatch failed: ${err instanceof Error ? err.message : String(err)}`,
          );
        }
        if (cmdId) {
          inst.cmdId = cmdId;
          tracker.dispatched(inst);
        } else {
          tracker.abandon(inst.index);
        }
      }),
    );
  } catch (err) {
    tracker.release();
    throw err;
  } finally {
    removeCleanup();
  }

  const launched = tracker.state.sandboxes.length;
  onLog(`Run ${runId} launched with ${launched} sandbox(es). You can disconnect now.`);
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

/**
 * `cmd.wait()` is one long HTTP request; a dropped connection makes it
 * throw while the worker keeps running. Re-fetch the command and wait
 * again instead of treating a network blip as a failed worker (which
 * used to stop the sandbox mid-run).
 */
/**
 * The Sandbox API answers 410 when a sandbox is gone: timed out or stopped.
 * Nothing on it can be reached again, so retrying is pointless and "leave
 * it for collect" is wrong. A 404 is ambiguous here (it can come from a
 * command or file lookup on a live sandbox); `collect` treats a 404 from
 * `Sandbox.get` itself as gone.
 *
 * Only structured SDK errors count (`APIError.response.status`, its JSON
 * error code, or a `StreamError` code), following `cause` chains. Message
 * text is ignored: error strings can carry worker stderr or tar output from
 * inside the sandbox, which must not be able to make the host abandon a
 * live sandbox.
 */
const GONE_CODES = new Set(["sandbox_stopped", "sandbox_not_found"]);

/** HTTP status of a structured SDK error (`APIError`), following `cause`. */
function sdkStatus(err: unknown): number | undefined {
  let e: unknown = err;
  for (let depth = 0; depth < 5 && e !== null && typeof e === "object"; depth++) {
    const status = (e as { response?: { status?: unknown } }).response?.status;
    if (typeof status === "number") return status;
    e = (e as { cause?: unknown }).cause;
  }
  return undefined;
}

export function isSandboxGone(err: unknown): boolean {
  let e: unknown = err;
  for (let depth = 0; depth < 5 && e !== null && typeof e === "object"; depth++) {
    const x = e as {
      name?: unknown;
      code?: unknown;
      response?: { status?: unknown };
      json?: { error?: { code?: unknown } };
      cause?: unknown;
    };
    if (x.response?.status === 410) return true;
    const jsonCode = x.json?.error?.code;
    if (typeof jsonCode === "string" && GONE_CODES.has(jsonCode)) return true;
    if (x.name === "StreamError" && typeof x.code === "string" && GONE_CODES.has(x.code))
      return true;
    e = x.cause;
  }
  return false;
}

export async function waitForCommand<C extends { wait(): Promise<unknown> }>(
  first: C,
  refetch: () => Promise<C>,
  label: string,
  onLog: (msg: string) => void,
  opts: { attempts?: number; delayMs?: number } = {},
): Promise<Awaited<ReturnType<C["wait"]>>> {
  const attempts = opts.attempts ?? 60;
  const delayMs = opts.delayMs ?? 10_000;
  let cmd = first;
  for (let attempt = 1; ; attempt++) {
    try {
      return (await cmd.wait()) as Awaited<ReturnType<C["wait"]>>;
    } catch (err) {
      if (attempt >= attempts || isSandboxGone(err)) throw err;
      const msg = err instanceof Error ? err.message : String(err);
      onLog(
        `${label} waiting for the command failed (${msg}); retrying in ${Math.round(delayMs / 1000)}s (${attempt}/${attempts})`,
      );
      await new Promise((r) => setTimeout(r, delayMs));
      try {
        cmd = await refetch();
      } catch {
        // keep the old handle; the next wait() may still work
      }
    }
  }
}

export async function collect(
  projectId: string,
  runId: string,
  onLog: (msg: string) => void,
): Promise<SandboxResult[]> {
  const state = loadRunState(projectId, runId);
  onLog(`Collecting run ${runId}: ${state.command} (${state.sandboxes.length} sandboxes)`);
  // Entries that still need a later collect: sandboxes left running because
  // a download failed, or that couldn't be reached. Everything else (done,
  // salvaged and stopped, or gone) leaves the run state.
  const retained = new Set<number>();

  // A worker that exited non-zero still has its successful batches'
  // results on disk. Returns false when the download failed, so the
  // sandbox is left running for another collect attempt.
  const salvageResults = async (
    sandbox: Sandbox,
    index: number,
    manifest: string[],
    workerRunId?: string,
  ): Promise<boolean> => {
    try {
      await downloadResults(sandbox, index, projectId, onLog);
      releaseUnfinished({ manifest, index, workerRunId }, projectId, onLog);
      return true;
    } catch (err) {
      onLog(
        `[sandbox-${index}] Download after failure did not complete: ${err instanceof Error ? err.message : String(err)}; leaving the sandbox running`,
      );
      retained.add(index);
      return false;
    }
  };

  const resultPromises = state.sandboxes.map(async (entry): Promise<SandboxResult> => {
    let lookedUp = false;
    try {
      const sandbox = await Sandbox.get({ sandboxId: entry.sandboxId });
      lookedUp = true;
      const cmd = await sandbox.getCommand(entry.cmdId);

      if (cmd.exitCode === null) {
        onLog(`[sandbox-${entry.index}] Still running, waiting...`);
        const waitPromise = waitForCommand(
          cmd,
          () => sandbox.getCommand(entry.cmdId),
          `[sandbox-${entry.index}]`,
          onLog,
        );
        waitPromise.catch(() => {});
        // Keep syncing results while we wait, as an attached run does, so a
        // reattached run doesn't hold everything until the worker exits.
        const stopPoller = { flag: false };
        const nudge = makeNudge();
        const pollerPromise = streamDownloadLoop(
          {
            sandbox,
            index: entry.index,
            sandboxId: entry.sandboxId,
            status: "running",
            manifest: entry.manifest,
          },
          projectId,
          onLog,
          stopPoller,
          nudge,
        );
        let finished: Awaited<typeof waitPromise>;
        try {
          await streamLogsCapped(
            cmd,
            `[sandbox-${entry.index}]`,
            onLog,
            (line) => {
              if (BATCH_COMPLETE_RE.test(line)) nudge.signal();
            },
            async () => {
              const timeout = new Promise<boolean>((resolve) =>
                setTimeout(() => resolve(false), 3000),
              );
              return Promise.race([
                waitPromise.then(
                  () => true,
                  () => true,
                ),
                timeout,
              ]);
            },
          );
          finished = await waitPromise;
        } finally {
          stopPoller.flag = true;
          nudge.signal();
          await pollerPromise;
        }
        if (finished.exitCode !== 0) {
          const stderr = await readStderrCapped(finished, 500);
          onLog(`[sandbox-${entry.index}] Failed (exit ${finished.exitCode})`);
          if (await salvageResults(sandbox, entry.index, entry.manifest, entry.workerRunId)) {
            try {
              await sandbox.stop();
            } catch {}
          }
          return {
            sandboxIndex: entry.index,
            sandboxId: entry.sandboxId,
            success: false,
            filesProcessed: 0,
            error: `Exit ${finished.exitCode}: ${stderr.slice(0, 500)}`,
          };
        }
      } else if (cmd.exitCode !== 0) {
        const stderr = await readStderrCapped(cmd, 500);
        onLog(`[sandbox-${entry.index}] Was failed (exit ${cmd.exitCode})`);
        if (await salvageResults(sandbox, entry.index, entry.manifest, entry.workerRunId)) {
          try {
            await sandbox.stop();
          } catch {}
        }
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
        releaseUnfinished(entry, projectId, onLog);
      } catch (err) {
        // The sandbox is the trust boundary; a download failure means we
        // either don't have the analysis output or it was rejected. Either
        // way, this run is NOT a clean success — report failure, leave the
        // sandbox + run state in place so the user can retry/inspect.
        const errMsg = err instanceof Error ? err.message : String(err);
        onLog(`[sandbox-${entry.index}] Download failed: ${errMsg}`);
        retained.add(entry.index);
        return {
          sandboxIndex: entry.index,
          sandboxId: entry.sandboxId,
          success: false,
          filesProcessed: 0,
          error: `Download failed: ${errMsg}`,
        };
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
      // Sandbox.get answering 404 means the sandbox no longer exists.
      if (isSandboxGone(err) || (!lookedUp && sdkStatus(err) === 404)) {
        // Nothing left to collect; give its unfinished files back.
        onLog(`[sandbox-${entry.index}] Sandbox is gone (timed out or stopped): ${errMsg}`);
        releaseUnfinished(entry, projectId, onLog);
      } else {
        onLog(`[sandbox-${entry.index}] Unreachable: ${errMsg}`);
        retained.add(entry.index);
      }
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

  // Keep only the entries a later collect can still act on. Partitions an
  // interrupted run never dispatched are dropped, so their files are free.
  const failed = results.filter((r) => !r.success).length;
  const remaining = state.sandboxes.filter((e) => retained.has(e.index));
  if (remaining.length === 0) {
    deleteRunState(projectId, runId);
    onLog(
      failed === 0
        ? `Run ${runId} collected and cleaned up.`
        : `Run ${runId}: ${failed}/${results.length} sandbox(es) failed; their results were salvaged or they are gone, so nothing is left to collect.`,
    );
  } else {
    updateRunState({ ...state, sandboxes: remaining, reserved: [] });
    onLog(
      `Run ${runId}: ${failed}/${results.length} sandbox(es) failed; keeping ${remaining.length} in the run state for another collect.`,
    );
  }

  return results;
}

/**
 * After a worker's results are downloaded, any of its files still marked
 * `processing` here never came back (the worker failed, or exited before
 * syncing them). Their locks name a run on the sandbox's host, so no later
 * local run would reclaim them; mark them `error` so the next run retries.
 * When the worker's run ID is known, only locks held by that run are
 * released, so another run's live lock on the same file is left alone.
 */
export function releaseUnfinished(
  inst: { manifest: string[]; index: number; workerRunId?: string },
  projectId: string,
  onLog: (msg: string) => void,
): void {
  let released = 0;
  for (const filePath of inst.manifest) {
    try {
      const record = readFileRecord(projectId, filePath);
      if (!record || record.status !== "processing") continue;
      if (inst.workerRunId) {
        if (record.lockedByRunId && record.lockedByRunId !== inst.workerRunId) continue;
      } else if (hasLiveLock(projectId, record)) {
        // Run state from an older version: without the worker's run ID,
        // leave any lock that may belong to a live run.
        continue;
      }
      record.status = "error";
      record.lockedByRunId = undefined;
      record.lockedAt = undefined;
      writeFileRecord(record);
      released++;
    } catch {}
  }
  if (released > 0) {
    onLog(
      `[sandbox-${inst.index}] ${released} file(s) did not finish; marked error for the next run`,
    );
  }
}

// --- Orchestrate (attached): bootstrap → spawn → run → download → stop ---

export async function orchestrate(
  config: SandboxConfig,
  onLog: (msg: string) => void,
): Promise<SandboxResult[]> {
  // Attached runs also save run state, so `sandbox collect` can reattach
  // if this process dies mid-run. The files are reserved at partitioning,
  // each worker is recorded when dispatched (so a crash during a staggered
  // ramp leaves every started worker recoverable), and it leaves the state
  // once its results are safely downloaded. A clean run ends with no state.
  const runId = generateRunId();
  const tracker = createRunStateTracker(config, runId, onLog);
  const removeCleanup = addShutdownCleanup(() => tracker.release());
  try {
    return await runAttached(config, onLog, runId, tracker);
  } catch (err) {
    tracker.release();
    throw err;
  } finally {
    removeCleanup();
  }
}

async function runAttached(
  config: SandboxConfig,
  onLog: (msg: string) => void,
  runId: string,
  tracker: ReturnType<typeof createRunStateTracker>,
): Promise<SandboxResult[]> {
  const { spawns, mode } = await bootstrapAndSpawn(config, onLog, (partitions) =>
    tracker.reserve(partitions),
  );

  if (spawns.length === 0) return [];

  onLog(`Dispatching '${config.command}' commands as sandboxes become ready...`);
  const instances: SandboxInstance[] = [];

  const runPromises = spawns.map(async (spawn) => {
    const inst = await spawn;
    instances.push(inst);
    // Start a background poller that streams deltas from the sandbox while
    // the worker runs. A nudge lets runOnSandboxAttached kick the poller as
    // soon as it sees "Batch N/M complete:" in the log.
    const stopPoller = { flag: false };
    const nudge = makeNudge();
    const pollerPromise =
      inst.status === "error"
        ? Promise.resolve()
        : streamDownloadLoop(inst, config.projectId, onLog, stopPoller, nudge);

    const result = await runOnSandboxAttached(inst, config, mode, onLog, nudge, () =>
      tracker.dispatched(inst),
    );
    if (!inst.cmdId) tracker.abandon(inst.index);
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
    // its last iteration and the worker exiting. The sandbox is the trust
    // boundary, so a failed download means the host didn't actually receive
    // the run's output — flip the result to failure rather than masquerading
    // as a clean run with empty findings.
    // Download even when the worker exited non-zero: `process` exits 1
    // when any batch errored, and the other batches' results are still on
    // the sandbox. Skip only sandboxes that never started the worker.
    // A failed result can also mean the host lost track of a worker that
    // is still running. Never download-release-stop such a sandbox; leave
    // it for `collect`. When its state can't be read, assume running.
    let stillRunning = false;
    let gone = inst.gone === true;
    if (inst.cmdId && !result.success && !gone) {
      try {
        stillRunning = (await inst.sandbox.getCommand(inst.cmdId)).exitCode == null;
      } catch (err) {
        gone = isSandboxGone(err);
        stillRunning = !gone;
      }
    }
    if (gone) {
      onLog(
        `[sandbox-${inst.index}] Sandbox is gone (timed out or stopped); results after its last sync are lost`,
      );
    }
    let downloadFailed = false;
    if (inst.cmdId && !stillRunning && !gone) {
      try {
        await downloadResults(inst.sandbox, inst.index, config.projectId, onLog);
      } catch (err) {
        downloadFailed = true;
        const errMsg = err instanceof Error ? err.message : String(err);
        onLog(`[sandbox-${inst.index}] Final download failed: ${errMsg}`);
        if (result.success) {
          result.success = false;
          result.error = `Download failed: ${errMsg}`;
        }
      }
    }
    const tDownload = Date.now();
    if (tDownload - tPoller > 500) {
      onLog(`[sandbox-${inst.index}] [debug] final downloadResults took ${tDownload - tPoller}ms`);
    }

    // Stopping deletes the sandbox's files. If its results never made it
    // here, leave it running (until its timeout) so `collect` can still
    // fetch them.
    if ((downloadFailed || stillRunning) && inst.cmdId) {
      untrackSandbox(inst.sandbox);
      onLog(
        `[sandbox-${inst.index}] ${stillRunning ? "Worker is still running; left" : "Left"} running so its results can be collected: pnpm deepsec sandbox collect --project-id ${config.projectId} --run-id ${runId}`,
      );
    } else {
      releaseUnfinished(inst, config.projectId, onLog);
      inst.collected = true;
      tracker.drop(inst.index);
      if (gone) {
        untrackSandbox(inst.sandbox);
      } else if (!config.keepAlive && inst.sandboxId) {
        try {
          await inst.sandbox.stop();
          onLog(`[sandbox-${inst.index}] Stopped.`);
        } catch {}
        untrackSandbox(inst.sandbox);
      }
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
      if (isSandboxGone(err)) {
        onLog(`[sandbox-${inst.index}] Sandbox is gone; stopping periodic sync`);
        break;
      }
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
  onDispatched?: () => void,
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

    const invocation = buildSandboxInvocation(config, mode, manifestPath, instance.workerRunId);
    onLog(
      `[sandbox-${index}] Running: deepsec ${config.command} (${manifest.length || "all"} files)...`,
    );

    const cmd = await sandbox.runCommand({
      cmd: invocation.cmd,
      args: invocation.args,
      cwd: DEEPSEC_DIR,
      detached: true,
    });
    instance.cmdId = cmd.cmdId;
    onDispatched?.();

    // Started before streaming so a closed log stream can tell whether the
    // command is really done or the stream just dropped.
    const waitPromise = waitForCommand(
      cmd,
      () => sandbox.getCommand(cmd.cmdId),
      `[sandbox-${index}]`,
      onLog,
    );
    waitPromise.catch(() => {});
    const isFinished = async () => {
      const timeout = new Promise<boolean>((resolve) => setTimeout(() => resolve(false), 3000));
      return Promise.race([
        waitPromise.then(
          () => true,
          () => true,
        ),
        timeout,
      ]);
    };
    await streamLogsCapped(
      cmd,
      `[sandbox-${index}]`,
      onLog,
      (line) => {
        if (nudge && BATCH_COMPLETE_RE.test(line)) {
          // Kick the streaming download loop to sync now — a batch
          // just finished and wrote file records to disk.
          nudge.signal();
        }
      },
      isFinished,
    );
    const tLogsClosed = Date.now();

    const result = await waitPromise;
    const tWaitReturned = Date.now();
    const waitGap = tWaitReturned - tLogsClosed;
    if (waitGap > 500) {
      onLog(`[sandbox-${index}] [debug] cmd.wait() lagged ${waitGap}ms after cmd.logs() closed`);
    }

    if (result.exitCode !== 0) {
      const stderr = await readStderrCapped(result, 500);
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
    // Decided from the SDK error itself, never from the message text.
    instance.gone = isSandboxGone(err);
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

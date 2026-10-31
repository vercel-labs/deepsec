import { execSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ensureFindingIds } from "./finding-id.js";
import {
  dataDir,
  fileRecordPath,
  filesDir,
  projectConfigPath,
  runMetaPath,
  runsDir,
} from "./paths.js";
import { projectConfigSchema, runMetaSchema, salvageFileRecord } from "./schemas.js";
import type { FileRecord, ProjectConfig, RunMeta } from "./types.js";

/**
 * Default parallelism: leave one core for the OS / orchestrator. Used as
 * the default `--concurrency` for `process`, `revalidate`, `triage`, and
 * `enrich`. Sandbox commands have their own default that's tied to vCPU
 * sizing.
 */
export function defaultConcurrency(): number {
  return Math.max(1, os.availableParallelism() - 1);
}

export function generateRunId(): string {
  const now = new Date();
  const ts = now.toISOString().replace(/[-:T]/g, "").slice(0, 14); // YYYYMMDDHHmmss
  const suffix = crypto.randomBytes(8).toString("hex"); // 16 hex chars / 64 bits
  return `${ts}-${suffix}`;
}

// --- Project config ---

function detectGithubUrl(rootPath: string): string | undefined {
  try {
    const remote = execSync("git remote get-url origin", {
      cwd: rootPath,
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 5000,
    }).trim();
    const branch = execSync("git rev-parse --abbrev-ref HEAD", {
      cwd: rootPath,
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 5000,
    }).trim();
    // Convert SSH to HTTPS
    const https = remote.replace(/^git@github\.com:/, "https://github.com/").replace(/\.git$/, "");
    if (https.includes("github.com")) {
      return `${https}/blob/${branch}`;
    }
  } catch {}
  return undefined;
}

export function ensureProject(projectId: string, rootPath: string): ProjectConfig {
  const configPath = projectConfigPath(projectId);
  if (fs.existsSync(configPath)) {
    try {
      const raw = JSON.parse(fs.readFileSync(configPath, "utf-8"));
      const config = projectConfigSchema.parse(raw);
      let changed = false;
      if (path.resolve(rootPath) !== config.rootPath) {
        config.rootPath = path.resolve(rootPath);
        changed = true;
      }
      if (!config.githubUrl) {
        config.githubUrl = detectGithubUrl(path.resolve(rootPath));
        if (config.githubUrl) changed = true;
      }
      if (changed) writeProjectConfig(configPath, config);
      return config;
    } catch {
      // project.json is generated state. An interrupted non-atomic write from
      // an older Deepsec version must not permanently wedge --force recovery.
    }
  }
  const config: ProjectConfig = {
    projectId,
    rootPath: path.resolve(rootPath),
    createdAt: new Date().toISOString(),
    githubUrl: detectGithubUrl(path.resolve(rootPath)),
  };
  fs.mkdirSync(path.dirname(configPath), { recursive: true });
  writeProjectConfig(configPath, config);
  return config;
}

function writeProjectConfig(file: string, config: ProjectConfig): void {
  const temp = `${file}.${process.pid}.${Math.random().toString(16).slice(2)}.tmp`;
  try {
    fs.writeFileSync(temp, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
    fs.renameSync(temp, file);
  } finally {
    if (fs.existsSync(temp)) fs.unlinkSync(temp);
  }
}

export function readProjectConfig(projectId: string): ProjectConfig {
  const configPath = projectConfigPath(projectId);
  const raw = JSON.parse(fs.readFileSync(configPath, "utf-8"));
  return projectConfigSchema.parse(raw);
}

// --- Run metadata ---

export function createRunMeta(params: {
  projectId: string;
  rootPath: string;
  type: RunMeta["type"];
  scannerConfig?: RunMeta["scannerConfig"];
  processorConfig?: RunMeta["processorConfig"];
}): RunMeta {
  const runId = generateRunId();
  const meta: RunMeta = {
    runId,
    projectId: params.projectId,
    rootPath: path.resolve(params.rootPath),
    createdAt: new Date().toISOString(),
    type: params.type,
    phase: "running",
    pid: process.pid,
    hostname: os.hostname(),
    scannerConfig: params.scannerConfig,
    processorConfig: params.processorConfig,
    stats: {},
  };
  return meta;
}

/**
 * Best-effort PID liveness check. `process.kill(pid, 0)` doesn't actually
 * signal the process — it just probes whether the kernel would deliver a
 * signal. ESRCH means "no such process" (genuinely dead). EPERM means the
 * PID exists but is owned by a different user, which on a single-user
 * developer machine effectively never happens; we treat it as "alive" to
 * stay on the safe side. Returns `true` on any other failure for the same
 * reason — false-positive reclaims clobber findings, false negatives just
 * cost a retry on the next run.
 */
export function isPidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ESRCH") return false;
    return true;
  }
}

export function writeRunMeta(meta: RunMeta): void {
  const metaPath = runMetaPath(meta.projectId, meta.runId);
  fs.mkdirSync(path.dirname(metaPath), { recursive: true });
  fs.writeFileSync(metaPath, JSON.stringify(meta, null, 2) + "\n");
}

export function readRunMeta(projectId: string, runId: string): RunMeta {
  const metaPath = runMetaPath(projectId, runId);
  const raw = JSON.parse(fs.readFileSync(metaPath, "utf-8"));
  return runMetaSchema.parse(raw);
}

export function completeRun(
  projectId: string,
  runId: string,
  phase: "done" | "error",
  stats?: Partial<RunMeta["stats"]>,
): void {
  const meta = readRunMeta(projectId, runId);
  meta.phase = phase;
  meta.completedAt = new Date().toISOString();
  if (stats) Object.assign(meta.stats, stats);
  writeRunMeta(meta);
}

// --- Run-level shutdown handling ---
//
// Why this exists: when the CLI gets Ctrl+C'd (SIGINT) or killed
// (SIGTERM), the long-running `process()` / `revalidate()` body exits
// without reaching its `completeRun(..., "done")` call. The run's
// RunMeta stays at `phase: "running"` forever, and every file the run
// claimed stays at `status: "processing"` with that run's lockedByRunId.
// The lock-reclaim logic only treats such locks as reclaimable after
// `STALE_LOCK_MS` (1h), so files are effectively stuck for an hour.
//
// We fix the graceful-shutdown case (~99% of interruptions) by flipping
// the run to `phase: "error"` from a SIGINT/SIGTERM handler. That single
// synchronous write makes every claimed file immediately reclaimable on
// the next invocation. Hard kills (SIGKILL / OOM / power) bypass this
// handler, but those are covered by the PID-liveness check in
// `isReclaimableLock`.
const activeRuns = new Map<string, { projectId: string; runId: string }>();
let shutdownHandlersInstalled = false;

function flushActiveRuns(): void {
  // Snapshot to a fresh array — completeRun's read+write can throw if
  // the meta file was already cleaned up, and we don't want one bad
  // entry to skip the rest.
  for (const { projectId, runId } of [...activeRuns.values()]) {
    try {
      // Only flip if the run is still "running". Sequential
      // process()/revalidate() calls in the same node process may
      // leave already-completed entries in the Map if the caller
      // forgets to unregister; flipping those would corrupt their
      // phase ("done" → "error").
      const meta = readRunMeta(projectId, runId);
      if (meta.phase !== "running") continue;
      completeRun(projectId, runId, "error");
    } catch {
      // best-effort
    }
  }
  activeRuns.clear();
}

function installShutdownHandlers(): void {
  if (shutdownHandlersInstalled) return;
  shutdownHandlersInstalled = true;
  const handler = (signal: NodeJS.Signals) => {
    flushActiveRuns();
    // Attaching a listener for SIGINT/SIGTERM suppresses Node's
    // default termination, so we have to provide an exit path
    // ourselves or the process hangs after Ctrl+C. When another
    // listener is also registered (e.g. the sandbox shutdown handler
    // in `deepsec/sandbox/shutdown.ts`), defer to it — that handler
    // needs async cleanup time and calls process.exit() itself once
    // its sandboxes have stopped (or its 10s timeout fires).
    //
    // listenerCount counts the currently-executing handler too, so
    // "1" means we're the only listener.
    if (process.listenerCount(signal) <= 1) {
      // Conventional signal exit codes: 128 + signal number
      // (SIGINT=2 → 130, SIGTERM=15 → 143).
      process.exit(signal === "SIGINT" ? 130 : 143);
    }
  };
  process.on("SIGINT", handler);
  process.on("SIGTERM", handler);
  // beforeExit covers the case where a thrown error bubbles out of
  // `process()` / `revalidate()` without `unregisterActiveRun` being
  // called — without this, the run would be stranded at `phase:
  // "running"` even though the node process is on its way out.
  process.on("beforeExit", flushActiveRuns);
}

/**
 * Register a run so that SIGINT/SIGTERM marks it as `phase: "error"`
 * before the process exits. Call `unregisterActiveRun` (returned) when
 * the run completes normally — leaving stale entries would cause us to
 * try to error-flip already-completed runs at process exit.
 */
export function registerActiveRun(projectId: string, runId: string): () => void {
  installShutdownHandlers();
  const key = `${projectId}::${runId}`;
  activeRuns.set(key, { projectId, runId });
  let unregistered = false;
  return () => {
    if (unregistered) return;
    unregistered = true;
    activeRuns.delete(key);
  };
}

export function listRuns(projectId: string): RunMeta[] {
  const dir = runsDir(projectId);
  if (!fs.existsSync(dir)) return [];

  const metas: RunMeta[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith(".json")) continue;
    try {
      const raw = JSON.parse(fs.readFileSync(path.join(dir, entry.name), "utf-8"));
      metas.push(runMetaSchema.parse(raw));
    } catch {
      // skip malformed
    }
  }
  return metas.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
}

// --- File records ---

export function readFileRecord(projectId: string, filePath: string): FileRecord | null {
  const p = fileRecordPath(projectId, filePath);
  if (!fs.existsSync(p)) return null;
  let raw: unknown;
  try {
    raw = JSON.parse(fs.readFileSync(p, "utf-8"));
  } catch (err) {
    console.warn(
      `[deepsec] skipping unreadable file record ${p}: ${err instanceof Error ? err.message : err}`,
    );
    return null;
  }
  const record = parseFileRecordSalvaging(raw, p);
  if (!record) return null;
  // Lazy backfill: records written before findingId existed get
  // deterministic IDs assigned in memory on every load (same inputs →
  // same IDs), and the IDs persist on the next write.
  ensureFindingIds(record);
  return record;
}

/**
 * Validate a raw record via `salvageFileRecord`, warning (never silently)
 * about anything dropped. One malformed finding used to fail the whole
 * record's parse and vanish the file's *valid* findings along with it —
 * 148 findings in one observed 12-run comparison. Returns null only when
 * the record envelope itself is invalid.
 */
function parseFileRecordSalvaging(raw: unknown, sourcePath: string): FileRecord | null {
  const salvaged = salvageFileRecord(raw);
  if (!salvaged.ok) {
    console.warn(`[deepsec] skipping invalid file record ${sourcePath}: ${salvaged.error}`);
    return null;
  }
  for (const dropped of salvaged.droppedFindings) {
    console.warn(
      `[deepsec] dropping malformed finding #${dropped.index} in ${sourcePath}: ${dropped.issues}`,
    );
  }
  return salvaged.record;
}

export function writeFileRecord(record: FileRecord): void {
  const p = fileRecordPath(record.projectId, record.filePath);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(record, null, 2) + "\n");
}

// --- Per-project process lock ---
//
// Mutex for the SELECTION + CLAIM phase of `process()`. Without it, two
// CLI invocations against the same project both load the same FileRecords,
// both filter to "pending", both write status="processing" with their own
// runId — the loser's lock + future analysisHistory writes get clobbered.
//
// Lock primitive: atomic `mkdir`. POSIX + Windows both make `mkdir` fail
// with EEXIST when the target exists, so the kernel does the
// mutual-exclusion for us. The lock holder writes a small `owner` file
// inside the dir so stale-lock detection can read who/when.
//
// Scope: only held during the few seconds of disk I/O it takes to choose
// + lock files. Real processing runs OUTSIDE the lock and in parallel
// with other concurrent runs on disjoint file sets.
const PROCESS_LOCK_DIR_NAME = ".process.lock";
const PROCESS_LOCK_STALE_MS = 60 * 60 * 1000; // 1h, matches per-file STALE_LOCK_MS

function processLockPath(projectId: string): string {
  return path.join(dataDir(projectId), PROCESS_LOCK_DIR_NAME);
}

/**
 * Acquire the per-project process lock. Polls every 200ms up to
 * `timeoutMs`. Returns a release function on success; throws on timeout.
 *
 * If we observe a lock dir older than 1h, we treat it as abandoned (the
 * holder crashed or got `kill -9`'d) and reclaim it. Same cutoff as the
 * per-file `STALE_LOCK_MS` so the two layers agree.
 */
export async function acquireProcessLock(
  projectId: string,
  ownerRunId: string,
  timeoutMs = 30_000,
): Promise<() => void> {
  const lockDir = processLockPath(projectId);
  fs.mkdirSync(path.dirname(lockDir), { recursive: true });
  const ownerFile = path.join(lockDir, "owner");
  const deadline = Date.now() + timeoutMs;
  while (true) {
    try {
      fs.mkdirSync(lockDir);
      try {
        fs.writeFileSync(
          ownerFile,
          JSON.stringify({ runId: ownerRunId, acquiredAt: new Date().toISOString() }),
        );
      } catch {
        // owner file is informational; lock works without it.
      }
      let released = false;
      return () => {
        if (released) return;
        released = true;
        try {
          fs.rmSync(lockDir, { recursive: true, force: true });
        } catch {}
      };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      // Held by someone else — check if it's stale.
      let mtime = 0;
      try {
        mtime = fs.statSync(ownerFile).mtimeMs;
      } catch {
        try {
          mtime = fs.statSync(lockDir).mtimeMs;
        } catch {
          // Lock vanished between mkdir EEXIST and stat — retry the mkdir.
          continue;
        }
      }
      if (Date.now() - mtime > PROCESS_LOCK_STALE_MS) {
        try {
          fs.rmSync(lockDir, { recursive: true, force: true });
        } catch {}
        continue;
      }
      if (Date.now() >= deadline) {
        throw new Error(
          `Timed out after ${timeoutMs}ms waiting for the process lock on project ${JSON.stringify(projectId)}. ` +
            `Another \`deepsec process\` is mid-claim. If no run is active, remove ${lockDir} manually.`,
        );
      }
      await new Promise((r) => setTimeout(r, 200));
    }
  }
}

export function loadAllFileRecords(projectId: string): FileRecord[] {
  const dir = filesDir(projectId);
  if (!fs.existsSync(dir)) return [];

  const records: FileRecord[] = [];
  function walk(dirPath: string) {
    for (const entry of fs.readdirSync(dirPath, { withFileTypes: true })) {
      const full = path.join(dirPath, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.name.endsWith(".json")) {
        let raw: unknown;
        try {
          raw = JSON.parse(fs.readFileSync(full, "utf-8"));
        } catch (err) {
          console.warn(
            `[deepsec] skipping unreadable file record ${full}: ${err instanceof Error ? err.message : err}`,
          );
          continue;
        }
        const record = parseFileRecordSalvaging(raw, full);
        if (!record) continue;
        ensureFindingIds(record); // see readFileRecord
        records.push(record);
      }
    }
  }
  walk(dir);
  return records;
}

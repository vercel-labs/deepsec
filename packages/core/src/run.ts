import { execSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  dataDir,
  fileRecordPath,
  filesDir,
  projectConfigPath,
  runMetaPath,
  runsDir,
} from "./paths.js";
import { fileRecordSchema, projectConfigSchema, runMetaSchema } from "./schemas.js";
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
    if (changed) {
      fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n");
    }
    return config;
  }
  const config: ProjectConfig = {
    projectId,
    rootPath: path.resolve(rootPath),
    createdAt: new Date().toISOString(),
    githubUrl: detectGithubUrl(path.resolve(rootPath)),
  };
  fs.mkdirSync(path.dirname(configPath), { recursive: true });
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n");
  return config;
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
    scannerConfig: params.scannerConfig,
    processorConfig: params.processorConfig,
    stats: {},
  };
  return meta;
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
  try {
    const raw = JSON.parse(fs.readFileSync(p, "utf-8"));
    return fileRecordSchema.parse(raw);
  } catch {
    return null;
  }
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
        try {
          const raw = JSON.parse(fs.readFileSync(full, "utf-8"));
          records.push(fileRecordSchema.parse(raw));
        } catch {
          // skip malformed
        }
      }
    }
  }
  walk(dir);
  return records;
}

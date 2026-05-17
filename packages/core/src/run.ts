import { execSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  dataDir,
  fileRecordPath,
  filesDir,
  getDataRoot,
  projectConfigPath,
  runMetaPath,
  runsDir,
} from "./paths.js";
import { fileRecordSchema, projectConfigSchema, runMetaSchema } from "./schemas.js";
import type { FileRecord, ProjectConfig, RunMeta } from "./types.js";

const SECRET_SLUGS = new Set([
  "secrets-exposure",
  "secrets-plaintext-exposure",
  "secret-in-fallback",
  "secret-in-log",
  "secret-env-var",
  "env-exposure",
  "jwt-handling",
  "algorithm-confusion",
  "cron-secret-check",
  "tf-secret-in-data",
  "k8s-secret-reference",
]);

const CREDENTIAL_RE =
  /(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|bearer|authorization|token)\s*[:=]\s*["']?[^"'\s]{8,}["']?|\bBearer\s+[A-Za-z0-9._~+/-]{16,}|sk_live_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{16,}|ghp_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{12,}|vck_[A-Za-z0-9_-]{12,}/gi;
const MAX_MODEL_TEXT_CHARS = 12_000;
const MAX_MODEL_TITLE_CHARS = 300;
const MAX_REFUSAL_RAW_CHARS = 2_000;

function truncate(value: string, maxChars: number): string {
  if (value.length <= maxChars) return value;
  return `${value.slice(0, maxChars)}\n[truncated ${value.length - maxChars} chars]`;
}

function redactSensitiveText(value: string): string {
  return value.replace(CREDENTIAL_RE, "[redacted: credential-shaped value]");
}

function sanitizeModelText(value: string, maxChars = MAX_MODEL_TEXT_CHARS): string {
  return truncate(redactSensitiveText(value), maxChars);
}

function sanitizeFileRecord(record: FileRecord): FileRecord {
  const parsed = fileRecordSchema.parse(record);
  return {
    ...parsed,
    candidates: parsed.candidates.map((c) => ({
      ...c,
      snippet: SECRET_SLUGS.has(c.vulnSlug)
        ? "[redacted: secret-bearing snippet]"
        : redactSensitiveText(c.snippet),
    })),
    findings: parsed.findings.map((f) => ({
      ...f,
      vulnSlug: sanitizeModelText(f.vulnSlug, 120),
      title: sanitizeModelText(f.title, MAX_MODEL_TITLE_CHARS),
      description: sanitizeModelText(f.description),
      recommendation: sanitizeModelText(f.recommendation),
      triage: f.triage
        ? {
            ...f.triage,
            reasoning: sanitizeModelText(f.triage.reasoning),
          }
        : f.triage,
      revalidation: f.revalidation
        ? {
            ...f.revalidation,
            reasoning: sanitizeModelText(f.revalidation.reasoning),
          }
        : f.revalidation,
    })),
    analysisHistory: parsed.analysisHistory.map((h) => ({
      ...h,
      codexStderr: h.codexStderr ? redactSensitiveText(h.codexStderr) : h.codexStderr,
      refusal: h.refusal
        ? {
            ...h.refusal,
            reason: h.refusal.reason
              ? sanitizeModelText(h.refusal.reason, 1_000)
              : h.refusal.reason,
            skipped: h.refusal.skipped?.map((s) => ({
              ...s,
              reason: sanitizeModelText(s.reason, 1_000),
            })),
            raw: h.refusal.raw
              ? sanitizeModelText(h.refusal.raw, MAX_REFUSAL_RAW_CHARS)
              : h.refusal.raw,
          }
        : h.refusal,
    })),
  };
}

function pathIsInside(parent: string, child: string): boolean {
  const rel = path.relative(parent, child);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

function ensureDataDirectoryNoSymlinks(dirPath: string): void {
  const dataRoot = path.resolve(getDataRoot());
  const absDir = path.resolve(dirPath);
  if (!pathIsInside(dataRoot, absDir)) {
    throw new Error(`Refusing to write outside DEEPSEC_DATA_ROOT: ${absDir}`);
  }

  try {
    const st = fs.lstatSync(dataRoot);
    if (st.isSymbolicLink()) {
      throw new Error(`Refusing to write through symlinked data directory: ${dataRoot}`);
    }
    if (!st.isDirectory()) {
      throw new Error(`Refusing to write through non-directory data path: ${dataRoot}`);
    }
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    fs.mkdirSync(dataRoot, { recursive: true });
  }

  let current = dataRoot;
  for (const segment of path.relative(dataRoot, absDir).split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    try {
      const st = fs.lstatSync(current);
      if (st.isSymbolicLink()) {
        throw new Error(`Refusing to write through symlinked data directory: ${current}`);
      }
      if (!st.isDirectory()) {
        throw new Error(`Refusing to write through non-directory data path: ${current}`);
      }
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
      fs.mkdirSync(current);
    }
  }
}

export function writeDataTextAtomic(filePath: string, data: string): void {
  ensureDataDirectoryNoSymlinks(path.dirname(filePath));
  const tmp = path.join(
    path.dirname(filePath),
    `.${path.basename(filePath)}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`,
  );
  const fd = fs.openSync(tmp, "wx", 0o600);
  let committed = false;
  try {
    fs.writeFileSync(fd, data, "utf-8");
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  try {
    fs.renameSync(tmp, filePath);
    committed = true;
  } finally {
    if (!committed) {
      try {
        fs.unlinkSync(tmp);
      } catch {}
    }
  }
  try {
    const dirFd = fs.openSync(path.dirname(filePath), "r");
    try {
      fs.fsyncSync(dirFd);
    } finally {
      fs.closeSync(dirFd);
    }
  } catch {
    // Directory fsync is best-effort on platforms/filesystems that allow it.
  }
}

function writeJsonAtomic(filePath: string, data: unknown): void {
  writeDataTextAtomic(filePath, JSON.stringify(data, null, 2) + "\n");
}

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
      timeout: 5000,
    }).trim();
    const branch = execSync("git rev-parse --abbrev-ref HEAD", {
      cwd: rootPath,
      encoding: "utf-8",
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
      writeJsonAtomic(configPath, config);
    }
    return config;
  }
  const config: ProjectConfig = {
    projectId,
    rootPath: path.resolve(rootPath),
    createdAt: new Date().toISOString(),
    githubUrl: detectGithubUrl(path.resolve(rootPath)),
  };
  writeJsonAtomic(configPath, config);
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
  const parsed = runMetaSchema.parse(meta);
  const metaPath = runMetaPath(meta.projectId, meta.runId);
  writeJsonAtomic(metaPath, parsed);
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
  const sanitized = sanitizeFileRecord(record);
  const p = fileRecordPath(sanitized.projectId, sanitized.filePath);
  writeJsonAtomic(p, sanitized);
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

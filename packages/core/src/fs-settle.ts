// Helpers for filesystems where a create syscall returns before the new
// entry is visible to path lookup.
//
// Observed on Docker Desktop / virtiofs bind mounts of a macOS host (the
// shape most agent sandboxes use): `mkdir`, `writeFile`, and `symlink`
// return success, but `lstat`/`realpath`/`existsSync` on the path they just
// created report ENOENT for the next 1-2ms. `open`/`read`/`write` against
// the same path work immediately — it is the lookup path that lags, not the
// data. Measured visibility: 0/10 at 0ms, 9/10 at 1ms, 10/10 at 2ms.
//
// POSIX says a create is durable when the syscall returns, so code that
// creates a directory and then stats it is correct and still breaks here.
// The fix is to wait out the lag.
//
// Use these ONLY right after this process created the path. Everywhere else
// the wait is pure cost: an absent path stays absent no matter how long you
// wait for it.

import fs from "node:fs";

// 100ms is ~50x the observed virtiofs window. Deliberately a flat wait
// rather than a poll-until-visible loop: it is a handful of call sites on
// one code path (workspace scaffolding), and the simplicity is worth more
// than the milliseconds.
const DEFAULT_BUDGET_MS = 100;

/**
 * How long to wait for a create to become visible. Mutagen-based file
 * sharing (Docker Desktop's "Synchronized file shares") can lag far longer
 * than virtiofs, so the wait is tunable via `DEEPSEC_FS_SETTLE_MS`. Set it
 * to 0 on a filesystem you know is coherent.
 */
export function settleBudgetMs(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.DEEPSEC_FS_SETTLE_MS;
  if (raw === undefined) return DEFAULT_BUDGET_MS;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed < 0) {
    throw new Error(`DEEPSEC_FS_SETTLE_MS must be a non-negative number, got "${raw}"`);
  }
  return parsed;
}

/**
 * Wait out the mount's create-to-lookup lag.
 *
 * Every caller here is synchronous (`ensureProject`, workspace
 * scaffolding), so a timer is not an option; `Atomics.wait` on an
 * uncontended buffer parks the thread instead of spinning the CPU.
 */
export function settleFs(env?: NodeJS.ProcessEnv): void {
  const ms = settleBudgetMs(env);
  if (ms <= 0) return;
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/**
 * `fs.existsSync` for a path another process just created — a "false" is
 * re-checked once after settling.
 */
export function existsSettled(target: string, env?: NodeJS.ProcessEnv): boolean {
  if (fs.existsSync(target)) return true;
  settleFs(env);
  return fs.existsSync(target);
}

/**
 * Recursive `mkdir` that leaves the directory visible to path lookup when
 * it returns.
 *
 * Node's recursive mkdir walks the path creating each missing component,
 * and on a lagging mount the freshly created parent can still be invisible
 * when it looks up the child — which surfaces as
 * `ENOENT: mkdir '<parent>/<child>'` for a path whose parent was just
 * created successfully. So ENOENT here means "too early", not "missing":
 * settle and try once more.
 */
export function mkdirSettled(target: string, env?: NodeJS.ProcessEnv): void {
  try {
    fs.mkdirSync(target, { recursive: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    settleFs(env);
    fs.mkdirSync(target, { recursive: true });
  }
  settleFs(env);
}

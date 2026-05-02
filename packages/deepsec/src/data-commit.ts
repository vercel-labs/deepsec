import { execFileSync } from "node:child_process";
import path from "node:path";
import { getDataRoot } from "@deepsec/core";

const DATA_DIR = path.resolve(getDataRoot());

// A git ref name. Validated up front so we can pass DATA_BRANCH to git
// without the shell interpreting `;`/`$(...)` etc. — git itself rejects
// many of these but we don't rely on that.
const REF_RE = /^[A-Za-z0-9._/-]+$/;
const RAW_BRANCH = process.env.DEEPSEC_DATA_BRANCH ?? "main";
if (!REF_RE.test(RAW_BRANCH)) {
  throw new Error(
    `Invalid DEEPSEC_DATA_BRANCH ${JSON.stringify(RAW_BRANCH)}: must match ${REF_RE}.`,
  );
}
const DATA_BRANCH = RAW_BRANCH;

/**
 * Commit any changes in the data repo and push to origin.
 * Used after local operations that modify file records.
 */
export function commitAndPushData(message: string): boolean {
  // Large data dirs (10k+ pending records) can blow past the default 1 MB
  // execSync buffer with a single `git status --porcelain` call.
  const MAX_BUFFER = 256 * 1024 * 1024;

  const status = execFileSync("git", ["status", "--porcelain"], {
    cwd: DATA_DIR,
    encoding: "utf-8",
    timeout: 10000,
    maxBuffer: MAX_BUFFER,
  }).trim();

  if (!status) return false;

  execFileSync("git", ["add", "-A"], {
    cwd: DATA_DIR,
    encoding: "utf-8",
    timeout: 60000,
    maxBuffer: MAX_BUFFER,
  });
  // argv form so `message` (and any caller-derived value like projectId)
  // is never re-parsed by a shell.
  execFileSync("git", ["commit", "-m", message], {
    cwd: DATA_DIR,
    encoding: "utf-8",
    timeout: 60000,
    maxBuffer: MAX_BUFFER,
  });

  let retries = 3;
  while (retries > 0) {
    try {
      execFileSync("git", ["pull", "--rebase", "origin", DATA_BRANCH], {
        cwd: DATA_DIR,
        encoding: "utf-8",
        timeout: 30000,
        maxBuffer: MAX_BUFFER,
      });
      execFileSync("git", ["push", "origin", `HEAD:${DATA_BRANCH}`], {
        cwd: DATA_DIR,
        encoding: "utf-8",
        timeout: 30000,
        maxBuffer: MAX_BUFFER,
      });
      return true;
    } catch {
      retries--;
      if (retries === 0) {
        console.error(
          `Failed to push data repo after 3 retries. Push manually: cd data && git push origin HEAD:${DATA_BRANCH}`,
        );
        return false;
      }
    }
  }
  return false;
}

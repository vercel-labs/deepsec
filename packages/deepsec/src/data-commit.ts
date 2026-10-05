import { execFileSync } from "node:child_process";
import fs from "node:fs";
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

// Matchers whose whole purpose is to flag credential-shaped strings — their
// `candidates[].snippet` will, by construction, sometimes contain real
// credentials lifted verbatim from the scanned source. Snippets are an
// optimization for the agent prompt; they get regenerated on the next scan,
// so dropping them from the committed cache is safe.
const SECRET_SLUGS = new Set([
  "secrets-exposure",
  "secret-in-fallback",
  "secret-in-log",
  "secret-env-var",
  "env-exposure",
  "laravel-config-exposure",
  "jwt-handling",
  "algorithm-confusion",
  "cron-secret-check",
]);

// Belt-and-suspenders sweep: if any leftover snippet looks like a hardcoded
// credential after slug-based scrubbing, fail the commit instead of pushing.
const CREDENTIAL_RE =
  /(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|bearer|authorization)\s*[:=]\s*["'][^"'\s]{8,}["']|sk_live_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{16,}|ghp_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{12,}/i;

/**
 * Walk `data/<projectId>/files/**.json`, drop snippets for matchers whose
 * job is to find credentials, and refuse to commit if any leftover candidate
 * snippet still matches a high-risk credential pattern.
 *
 * Mutates files on disk in place — caller invokes us before `git add -A`.
 */
function scrubCommittedDataDir(): void {
  const stack = [DATA_DIR];
  const offenders: string[] = [];
  while (stack.length > 0) {
    const dir = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) {
        // Only recurse into the per-project files/ tree — that's where
        // scanner snippets live.
        if (dir === DATA_DIR || /(?:^|\/)files(?:$|\/)/.test(p) || e.name === "files") {
          stack.push(p);
        } else if (/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(e.name)) {
          // top-level project dirs
          stack.push(p);
        }
        continue;
      }
      if (!p.endsWith(".json")) continue;
      if (!p.includes(`${path.sep}files${path.sep}`)) continue;
      let raw: string;
      try {
        raw = fs.readFileSync(p, "utf-8");
      } catch {
        continue;
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        continue;
      }
      if (!parsed || typeof parsed !== "object") continue;
      const rec = parsed as {
        candidates?: Array<{ vulnSlug?: string; snippet?: string }>;
      };
      let changed = false;
      for (const c of rec.candidates ?? []) {
        if (c.vulnSlug && SECRET_SLUGS.has(c.vulnSlug) && c.snippet) {
          c.snippet = "[redacted: secret-bearing snippet]";
          changed = true;
          continue;
        }
        if (c.snippet && CREDENTIAL_RE.test(c.snippet)) {
          offenders.push(`${p} (slug=${c.vulnSlug ?? "?"})`);
        }
      }
      if (changed) {
        fs.writeFileSync(p, JSON.stringify(rec, null, 2) + "\n");
      }
    }
  }
  if (offenders.length > 0) {
    throw new Error(
      `Refusing to commit: ${offenders.length} candidate snippet(s) still match credential patterns after scrubbing. ` +
        `Fix the matcher's slug or extend SECRET_SLUGS in data-commit.ts:\n  ${offenders.slice(0, 5).join("\n  ")}` +
        (offenders.length > 5 ? `\n  …and ${offenders.length - 5} more` : ""),
    );
  }
}

/**
 * Commit any changes in the data repo and push to origin.
 * Used after local operations that modify file records.
 */
export function commitAndPushData(message: string): boolean {
  // Large data dirs (10k+ pending records) can blow past the default 1 MB
  // execSync buffer with a single `git status --porcelain` call.
  const MAX_BUFFER = 256 * 1024 * 1024;

  // Drop credential-shaped snippets BEFORE git sees the files; if anything
  // looks like a real secret after scrubbing, we throw and the commit
  // doesn't happen.
  scrubCommittedDataDir();

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

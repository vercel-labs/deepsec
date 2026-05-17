import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { IGNORE_DIRS } from "@deepsec/scanner";
import { minimatch } from "minimatch";

/**
 * Resolve a file list for `process` direct-invocation modes (`--diff`,
 * `--diff-staged`, `--diff-working`, `--files`, `--files-from`).
 *
 * Exactly one source must be specified — the CLI enforces mutual
 * exclusivity. Output paths are POSIX-relative to `rootPath`, deduped,
 * filtered to existing files, and (unless `noIgnore`) filtered through
 * the scanner's `IGNORE_DIRS` so PRs touching `dist/**` or `*.test.ts`
 * don't burn AI budget.
 */
export function resolveFiles(opts: {
  rootPath: string;
  diff?: string;
  diffStaged?: boolean;
  diffWorking?: boolean;
  files?: string[];
  filesFrom?: string;
  /** Bypass IGNORE_DIRS filtering (caller explicitly opted in). */
  noIgnore?: boolean;
}): { filePaths: string[]; sourceLabel: string; skipped: Array<{ path: string; reason: string }> } {
  const sources: string[] = [];
  if (opts.diff !== undefined) sources.push("--diff");
  if (opts.diffStaged) sources.push("--diff-staged");
  if (opts.diffWorking) sources.push("--diff-working");
  if (opts.files && opts.files.length > 0) sources.push("--files");
  if (opts.filesFrom) sources.push("--files-from");
  if (sources.length === 0) {
    throw new Error("resolveFiles: no source specified");
  }
  if (sources.length > 1) {
    throw new Error(`Conflicting file sources: ${sources.join(", ")}. Pick exactly one.`);
  }

  const absRoot = path.resolve(opts.rootPath);
  let raw: string[];
  let rawFromGit = false;
  let sourceLabel: string;

  if (opts.diff !== undefined) {
    validateGitRefArg(opts.diff);
    raw = gitDiffNames(absRoot, [
      "diff",
      "--name-only",
      "-z",
      "--diff-filter=AMRC",
      opts.diff,
      "--",
    ]);
    rawFromGit = true;
    sourceLabel = `git-diff:${opts.diff}`;
  } else if (opts.diffStaged) {
    raw = gitDiffNames(absRoot, ["diff", "--name-only", "-z", "--diff-filter=AMRC", "--cached"]);
    rawFromGit = true;
    sourceLabel = "git-diff:staged";
  } else if (opts.diffWorking) {
    // Working tree: tracked changes + untracked files. `ls-files` is the
    // simplest way to capture untracked-but-not-ignored.
    const tracked = gitDiffNames(absRoot, ["diff", "--name-only", "-z", "--diff-filter=AMRC"]);
    const untracked = gitDiffNames(absRoot, ["ls-files", "--others", "--exclude-standard", "-z"]);
    raw = [...tracked, ...untracked];
    rawFromGit = true;
    sourceLabel = "git-diff:working";
  } else if (opts.files && opts.files.length > 0) {
    raw = opts.files;
    sourceLabel = "files:cli";
  } else if (opts.filesFrom) {
    raw = readLinesFromFile(opts.filesFrom);
    sourceLabel = `files-from:${opts.filesFrom === "-" ? "stdin" : opts.filesFrom}`;
  } else {
    throw new Error("unreachable");
  }

  // Normalize, dedupe, and filter to files that actually exist under root.
  const seen = new Set<string>();
  const out: string[] = [];
  const skipped: Array<{ path: string; reason: string }> = [];
  for (const entry of raw) {
    const input = rawFromGit ? entry : entry.trim();
    if (!input) continue;
    let rel = rawFromGit ? input : input.replaceAll("\\", "/");
    // Drop a leading "./" which `git diff` doesn't produce but humans pass via --files.
    if (rel.startsWith("./")) rel = rel.slice(2);
    // Reject absolute paths that escape root, accept absolute paths under root.
    const abs = path.resolve(absRoot, rel);
    if (!isInside(absRoot, abs)) {
      skipped.push({ path: input, reason: "outside root" });
      continue;
    }
    rel = rawFromGit
      ? path.relative(absRoot, abs)
      : path.relative(absRoot, abs).replaceAll("\\", "/");
    if (!isSafeRelativeFilePath(rel)) {
      skipped.push({ path: input, reason: "unsafe path" });
      continue;
    }
    if (seen.has(rel)) continue;

    let st: fs.Stats;
    try {
      st = fs.lstatSync(abs);
    } catch {
      skipped.push({ path: rel, reason: "missing" });
      continue;
    }
    if (st.isSymbolicLink()) {
      skipped.push({ path: rel, reason: "symlink" });
      continue;
    }
    if (!st.isFile()) {
      skipped.push({ path: rel, reason: "not a file" });
      continue;
    }

    let real: string;
    try {
      real = fs.realpathSync(abs);
    } catch {
      skipped.push({ path: rel, reason: "unresolvable realpath" });
      continue;
    }
    if (!isInside(fs.realpathSync(absRoot), real)) {
      skipped.push({ path: rel, reason: "realpath outside root" });
      continue;
    }

    if (!opts.noIgnore && matchesAnyGlob(rel, IGNORE_DIRS)) {
      skipped.push({ path: rel, reason: "ignored" });
      continue;
    }

    seen.add(rel);
    out.push(rel);
  }

  return { filePaths: out, sourceLabel, skipped };
}

function validateGitRefArg(ref: string): void {
  if (ref.startsWith("-")) {
    throw new Error(`Invalid --diff ref ${JSON.stringify(ref)}: refs must not start with '-'`);
  }
}

function isInside(root: string, candidate: string): boolean {
  const rel = path.relative(root, candidate);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

function isSafeRelativeFilePath(filePath: string): boolean {
  if (!filePath || filePath.includes("\0") || filePath.includes("\\")) return false;
  if (path.isAbsolute(filePath)) return false;
  return filePath.split("/").every((part) => part !== "" && part !== "." && part !== "..");
}

function gitDiffNames(cwd: string, args: string[]): string[] {
  const result = spawnSync("git", args, {
    cwd,
    encoding: "buffer",
    timeout: 30_000,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error) {
    throw new Error(`git ${args.join(" ")} failed: ${result.error.message}`);
  }
  if (result.status !== 0) {
    const stderr = Buffer.from(result.stderr ?? "")
      .toString("utf8")
      .trim();
    throw new Error(`git ${args.join(" ")} exited ${result.status}${stderr ? `: ${stderr}` : ""}`);
  }
  return Buffer.from(result.stdout ?? "")
    .toString("utf8")
    .split("\0")
    .filter(Boolean);
}

function readLinesFromFile(p: string): string[] {
  if (p === "-") {
    let data = "";
    try {
      // 0 is stdin's fd; readFileSync on it works on POSIX and Windows.
      data = fs.readFileSync(0, "utf-8");
    } catch (err) {
      throw new Error(
        `Could not read file list from stdin: ${err instanceof Error ? err.message : err}`,
      );
    }
    return data.split("\n");
  }
  if (!fs.existsSync(p)) {
    throw new Error(`--files-from: file not found: ${p}`);
  }
  return fs.readFileSync(p, "utf-8").split("\n");
}

function matchesAnyGlob(rel: string, globs: string[]): boolean {
  return globs.some((g) => minimatch(rel, g, { dot: true, nocase: false }));
}

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { deepsecDataIgnoreGlobs, IGNORE_DIRS } from "@deepsec/scanner";
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
}): { filePaths: string[]; sourceLabel: string } {
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
  const ignoreGlobs = [...IGNORE_DIRS, ...deepsecDataIgnoreGlobs(absRoot)];
  let raw: string[];
  let sourceLabel: string;

  if (opts.diff !== undefined) {
    raw = gitDiffNames(absRoot, ["diff", "--name-only", "--diff-filter=AMRC", opts.diff]);
    sourceLabel = `git-diff:${opts.diff}`;
  } else if (opts.diffStaged) {
    raw = gitDiffNames(absRoot, ["diff", "--name-only", "--diff-filter=AMRC", "--cached"]);
    sourceLabel = "git-diff:staged";
  } else if (opts.diffWorking) {
    // Working tree: tracked changes + untracked files. `ls-files` is the
    // simplest way to capture untracked-but-not-ignored.
    const tracked = gitDiffNames(absRoot, ["diff", "--name-only", "--diff-filter=AMRC"]);
    const untracked = gitDiffNames(absRoot, ["ls-files", "--others", "--exclude-standard"]);
    raw = [...tracked, ...untracked];
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
  for (const entry of raw) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    let rel = trimmed.replaceAll("\\", "/");
    // Drop a leading "./" which `git diff` doesn't produce but humans pass via --files.
    if (rel.startsWith("./")) rel = rel.slice(2);
    // Reject absolute paths that escape root, accept absolute paths under root.
    if (path.isAbsolute(rel)) {
      const absOf = path.resolve(rel);
      if (!absOf.startsWith(absRoot + path.sep) && absOf !== absRoot) continue;
      rel = path.relative(absRoot, absOf).replaceAll("\\", "/");
    }
    if (rel.startsWith("../") || rel === "..") continue;
    if (seen.has(rel)) continue;

    const abs = path.join(absRoot, rel);
    if (!fs.existsSync(abs)) continue;
    if (!fs.statSync(abs).isFile()) continue;

    if (!opts.noIgnore && matchesAnyGlob(rel, ignoreGlobs)) continue;

    seen.add(rel);
    out.push(rel);
  }

  return { filePaths: out, sourceLabel };
}

function gitDiffNames(cwd: string, args: string[]): string[] {
  const result = spawnSync("git", args, {
    cwd,
    encoding: "utf-8",
    timeout: 30_000,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error) {
    throw new Error(`git ${args.join(" ")} failed: ${result.error.message}`);
  }
  if (result.status !== 0) {
    const stderr = (result.stderr ?? "").toString().trim();
    throw new Error(`git ${args.join(" ")} exited ${result.status}${stderr ? `: ${stderr}` : ""}`);
  }
  return (result.stdout ?? "").split("\n").filter(Boolean);
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

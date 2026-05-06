import { execSync, spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { Sandbox } from "@vercel/sandbox";

export const TARGET_EXCLUDES = [
  "--exclude=node_modules",
  "--exclude=.next",
  "--exclude=.turbo",
  "--exclude=dist",
  "--exclude=.vercel",
  "--exclude=.cache",
  "--exclude=coverage",
  "--exclude=.git",
  "--exclude=*.log",
  "--exclude=.DS_Store",
];

export const DATA_EXCLUDES: string[] = [];

export const DEEPSEC_APP_EXCLUDES = [
  "--exclude=node_modules",
  "--exclude=.git",
  "--exclude=dist",
  "--exclude=.turbo",
  "--exclude=.next",
  "--exclude=coverage",
  "--exclude=data", // uploaded separately per project
  "--exclude=.DS_Store",
  "--exclude=*.log",
];

export interface TarballStats {
  /**
   * Absolute path to a temp file holding the gzipped tar. The caller owns
   * cleanup — once the upload (or whatever else needs the bytes) is done,
   * unlink this file. We hand back a path instead of a Buffer so the three
   * bundle tarballs (app/target/data) don't all sit in RAM at once: prior
   * to this change a 3×500 MB upload bundle held ~1.5 GB of resident memory
   * across the entire bootstrap; now each tarball is held in memory only
   * for the duration of its own writeFiles call.
   */
  tarPath: string;
  bytes: number;
  sha256: string;
}

/**
 * Tar + gzip `sourceDir` contents into a temp file on disk.
 *
 * If `sourceDir` is a git repository, honors `.gitignore` by feeding tar
 * the file list from `git ls-files --cached --others --exclude-standard`.
 * This drops `.next`, `dist`, `.env*`, build artifacts, IDE state, and
 * anything else the repo has gitignored — typically a 5-20× size reduction
 * on real projects.
 *
 * If not a git repo, falls back to the provided exclude list.
 *
 * Spawns the system `tar` rather than going through the `tar` npm package:
 * for many-small-files repos that's 2-3x faster on the archive step,
 * which on cold uploads is enough wall time to notice.
 *
 * The gzipped stream is piped through a SHA256 transform straight to disk
 * so we never hold a full-size Buffer in memory. Caller gets a path and
 * owns cleanup (uploadTarballToSandbox unlinks by default).
 */
export async function makeTarball(
  sourceDir: string,
  excludes: string[],
  onLog?: (msg: string) => void,
): Promise<TarballStats> {
  const started = Date.now();
  // Callers pass sourceDir as either an absolute or a process-cwd-relative
  // path (e.g. `data/<id>` from dataDir()). Resolve once so the spawn's
  // `cwd` and tar's `-C` arg can't disagree — passing a relative cwd to
  // spawn AND a relative `-C` to tar would double-apply: the child's
  // process.cwd() becomes `<process.cwd()>/<sourceDir>`, then tar's
  // `-C <sourceDir>` chdirs again to `<process.cwd()>/<sourceDir>/<sourceDir>`.
  const absSourceDir = path.resolve(sourceDir);
  const isGit = fs.existsSync(path.join(absSourceDir, ".git"));

  // Use a per-call unique filename so parallel makeTarball calls (the
  // orchestrator fires three at once) can't collide.
  const tarPath = path.join(
    os.tmpdir(),
    `deepsec-tar-${process.pid}-${Date.now()}-${crypto.randomBytes(4).toString("hex")}.tar.gz`,
  );

  if (isGit) {
    onLog?.(`Tarballing ${sourceDir} → ${path.basename(tarPath)} (using git ls-files)...`);
  } else {
    onLog?.(`Tarballing ${sourceDir} → ${path.basename(tarPath)} (no .git — exclude list)...`);
  }

  // SHA256-then-write transform: update the hash on each chunk, count
  // bytes, pass through to disk. Avoids an extra re-read pass.
  const hash = crypto.createHash("sha256");
  let bytes = 0;
  const sha256Tap = new Transform({
    transform(chunk: Buffer, _enc, cb) {
      hash.update(chunk);
      bytes += chunk.length;
      cb(null, chunk);
    },
  });

  let tar: ReturnType<typeof spawn>;
  let filteredList: Buffer | null = null;

  if (isGit) {
    // git ls-files -z emits NUL-separated paths. Tracked + untracked-not-ignored.
    // Filter via lstat: drop tracked-but-deleted (would error tar) and
    // symlinks (a tracked link → /Users/foo/secret would land in the
    // sandbox as a dangling pointer; harmless but a needless surprise
    // for matchers, and not something the user expects to upload).
    const raw = execSync("git ls-files --cached --others --exclude-standard -z", {
      cwd: absSourceDir,
      maxBuffer: 512 * 1024 * 1024,
    });
    const candidates = raw.toString("utf8").split("\0").filter(Boolean);
    let skippedDeleted = 0;
    let skippedSymlink = 0;
    const existing: string[] = [];
    for (const p of candidates) {
      let st: fs.Stats;
      try {
        st = fs.lstatSync(path.join(absSourceDir, p));
      } catch {
        skippedDeleted++;
        continue;
      }
      if (st.isSymbolicLink()) {
        skippedSymlink++;
        continue;
      }
      existing.push(p);
    }
    if (skippedDeleted > 0) {
      onLog?.(`  (skipped ${skippedDeleted} tracked-but-deleted file(s))`);
    }
    if (skippedSymlink > 0) {
      onLog?.(`  (skipped ${skippedSymlink} symlink(s))`);
    }
    filteredList = Buffer.from(`${existing.join("\0")}\0`);

    // `-C` MUST come before `-T -` in GNU tar. -T reads filenames from
    // stdin, and tar processes positional opts in argv order: anything
    // after -T - is treated as additional file specs, not options.
    // Recent GNU tar (≥1.35 on Linux CI) makes this a hard error
    // ("tar: -C '...' has no effect, exit 2") instead of the earlier
    // silent ignore. macOS bsdtar accepts both orders. We also set
    // `cwd: absSourceDir` on the spawn as a belt-and-suspenders for
    // the same reason — paths in the stdin list are relative, so the
    // initial cwd has to be right even before `-C` is parsed.
    // Both args must be absolute so a relative sourceDir doesn't
    // double-apply (spawn cwd resolves `data/x` against process.cwd
    // → relative `-C data/x` would then chdir again).
    tar = spawn("tar", ["-czf", "-", "-C", absSourceDir, "--null", "-T", "-"], {
      cwd: absSourceDir,
      stdio: ["pipe", "pipe", "pipe"],
      // macOS tar adds AppleDouble `._<file>` metadata entries by default.
      // Suppress so the sandbox doesn't see them — and so the host-side
      // strict extract on the return trip doesn't refuse them.
      env: { ...process.env, COPYFILE_DISABLE: "1" },
    });
  } else {
    // Same belt-and-suspenders pairing as the git branch above. Here
    // `-C` already runs before `.` so the initial cwd never mattered
    // for production — adding `cwd` doesn't change anything but keeps
    // the two branches symmetric. Absolute paths everywhere (see
    // absSourceDir comment above) so relative sourceDirs don't
    // double-apply. Only caller of this branch today is the data dir
    // (our own JSON output) which never has symlinks, so we don't
    // pre-filter here — tar would archive symlinks-as-links by default
    // anyway, which is safe; the host-side strict extract would
    // refuse them on the way back if any ever appeared.
    tar = spawn("tar", ["-czf", "-", ...excludes, "-C", absSourceDir, "."], {
      cwd: absSourceDir,
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, COPYFILE_DISABLE: "1" },
    });
  }

  // Capture stderr for error reporting. It's bounded (tar emits at most
  // a few KB of warnings/errors) so a plain accumulator is fine.
  const stderrChunks: Buffer[] = [];
  tar.stderr?.on("data", (c: Buffer) => stderrChunks.push(c));

  // Wait for tar to exit; pipeline alone won't tell us a non-zero exit.
  const exitPromise = new Promise<number>((resolve, reject) => {
    tar.once("error", reject);
    tar.once("close", resolve);
  });

  // Feed the git branch's path list via stdin before piping stdout.
  // `tar.stdin.end(buf)` writes and closes atomically.
  if (filteredList !== null && tar.stdin) {
    tar.stdin.end(filteredList);
  }

  // pipeline: tar.stdout → sha256Tap → disk. If any stage errors,
  // pipeline propagates it and the tar child is killed via its stdout
  // closing. On success, all three streams close cleanly.
  const fileOut = fs.createWriteStream(tarPath);
  try {
    await pipeline(tar.stdout!, sha256Tap, fileOut);
  } catch (err) {
    // If the pipeline fails, the temp file may be partial — nuke it.
    try {
      fs.unlinkSync(tarPath);
    } catch {}
    throw err;
  }
  const exitCode = await exitPromise;
  if (exitCode !== 0) {
    try {
      fs.unlinkSync(tarPath);
    } catch {}
    throw new Error(
      `tar exited ${exitCode}: ${Buffer.concat(stderrChunks).toString().slice(0, 500)}`,
    );
  }

  const sha256 = hash.digest("hex");
  const mb = (bytes / 1024 / 1024).toFixed(1);
  const secs = ((Date.now() - started) / 1000).toFixed(1);
  onLog?.(`Tarballed ${sourceDir} → ${mb}MB in ${secs}s (sha256:${sha256.slice(0, 12)}...)`);
  return { tarPath, bytes, sha256 };
}

/**
 * Upload a local tarball file to a path on the sandbox.
 *
 * Reads the local tarball into memory only at upload time and frees it
 * (along with the local temp file) immediately after, so callers that
 * build several tarballs in parallel don't keep all of them resident.
 *
 * The SDK's `writeFiles` API accepts only `string | Uint8Array` for
 * `content` — there's no public streaming-upload path in `@vercel/sandbox`
 * today, so we still hold one full Buffer for the duration of this call.
 * That's the smallest memory footprint achievable through the SDK; the
 * win vs. the previous design is that the Buffer's lifetime is now
 * scoped to a single call instead of the entire orchestration window.
 *
 * Pass `keepLocal: true` if the caller wants to retain the local file
 * (e.g. for retries). Default is to unlink on success.
 */
export async function uploadTarballToSandbox(
  sandbox: Sandbox,
  remoteTarPath: string,
  localTarPath: string,
  onLog?: (msg: string) => void,
  opts: { keepLocal?: boolean } = {},
): Promise<void> {
  const size = fs.statSync(localTarPath).size;
  const mb = (size / 1024 / 1024).toFixed(1);
  onLog?.(`Uploading ${remoteTarPath} (${mb}MB)...`);
  const started = Date.now();
  // Read just-in-time so that, in the parallel-upload case, only the
  // tarball currently in flight is resident in this process. (The SDK
  // internally re-tars+gzips into a second buffer; that's its concern.)
  const buffer = fs.readFileSync(localTarPath);
  try {
    await sandbox.writeFiles([{ path: remoteTarPath, content: buffer }]);
  } finally {
    // Buffer goes out of scope here; explicit `= null` would help GC
    // earlier but V8's escape analysis already does this. The local
    // file is the only thing left to clean up.
    if (!opts.keepLocal) {
      try {
        fs.unlinkSync(localTarPath);
      } catch {}
    }
  }
  onLog?.(`Uploaded ${remoteTarPath} in ${((Date.now() - started) / 1000).toFixed(1)}s`);
}

/**
 * Extract a tarball on the sandbox into destDir. Creates destDir if missing.
 */
export async function extractTarballOnSandbox(
  sandbox: Sandbox,
  remoteTarPath: string,
  destDir: string,
  onLog?: (msg: string) => void,
): Promise<void> {
  onLog?.(`Extracting ${remoteTarPath} → ${destDir}...`);
  const mkdir = await sandbox.runCommand({
    cmd: "mkdir",
    args: ["-p", destDir],
  });
  if (mkdir.exitCode !== 0) {
    throw new Error(`mkdir -p ${destDir} failed (exit ${mkdir.exitCode})`);
  }
  const extract = await sandbox.runCommand({
    cmd: "tar",
    args: ["-xzf", remoteTarPath, "-C", destDir],
  });
  if (extract.exitCode !== 0) {
    const err = await extract.stderr();
    throw new Error(
      `tar -xzf ${remoteTarPath} failed (exit ${extract.exitCode}): ${err.slice(0, 500)}`,
    );
  }
  // Remove the tarball to free space
  await sandbox.runCommand({ cmd: "rm", args: ["-f", remoteTarPath] });
}

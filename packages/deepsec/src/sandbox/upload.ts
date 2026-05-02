import { execSync, spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
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
  buffer: Buffer;
  bytes: number;
  sha256: string;
}

/**
 * Tar + gzip `sourceDir` contents into a Buffer.
 *
 * If `sourceDir` is a git repository, honors `.gitignore` by feeding tar
 * the file list from `git ls-files --cached --others --exclude-standard`.
 * This drops `.next`, `dist`, `.env*`, build artifacts, IDE state, and
 * anything else the repo has gitignored — typically a 5-20× size reduction
 * on real projects.
 *
 * If not a git repo, falls back to the provided exclude list.
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

  if (isGit) {
    onLog?.(`Tarballing ${sourceDir} (using git ls-files)...`);
  } else {
    onLog?.(`Tarballing ${sourceDir} (no .git — using exclude list)...`);
  }

  return await new Promise<TarballStats>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let stderr = "";

    const onDone = (code: number | null) => {
      if (code !== 0) {
        reject(new Error(`tar exited ${code}: ${stderr.slice(0, 500)}`));
        return;
      }
      const buffer = Buffer.concat(chunks);
      const sha256 = crypto.createHash("sha256").update(buffer).digest("hex");
      const mb = (buffer.length / 1024 / 1024).toFixed(1);
      const secs = ((Date.now() - started) / 1000).toFixed(1);
      onLog?.(`Tarballed ${sourceDir} → ${mb}MB in ${secs}s (sha256:${sha256.slice(0, 12)}...)`);
      resolve({ buffer, bytes: buffer.length, sha256 });
    };

    if (isGit) {
      // git ls-files -z emits NUL-separated paths. Tracked + untracked-not-ignored.
      // ls-files includes tracked-but-deleted entries (ones the user removed
      // locally without committing), so we filter by fs.existsSync before
      // handing the list to tar — otherwise tar errors on the missing files.
      const raw = execSync("git ls-files --cached --others --exclude-standard -z", {
        cwd: absSourceDir,
        maxBuffer: 512 * 1024 * 1024,
      });
      const paths = raw.toString("utf8").split("\0").filter(Boolean);
      const existing = paths.filter((p) => fs.existsSync(path.join(absSourceDir, p)));
      const skipped = paths.length - existing.length;
      if (skipped > 0) {
        onLog?.(`  (skipped ${skipped} tracked-but-deleted file(s))`);
      }
      const filtered = Buffer.from(existing.join("\0") + "\0");

      // Set both `cwd: absSourceDir` AND `-C absSourceDir`. They're
      // equivalent when production hits the non-git branch (where `-C`
      // is processed before the `.` file arg), but in the git branch
      // GNU tar reads paths from `-T -` in argv order — if `-C` lands
      // AFTER `-T -`, tar starts statting paths against the inherited
      // cwd before the chdir takes effect. Setting `cwd` on the spawn
      // fixes the initial dir; the `-C` arg stays as a redundant safety
      // net. Both must be absolute so a relative sourceDir doesn't
      // double-apply (spawn cwd resolves `data/x` against process.cwd
      // → relative `-C data/x` would then chdir again).
      const tar = spawn("tar", ["-czf", "-", "--null", "-T", "-", "-C", absSourceDir], {
        cwd: absSourceDir,
        stdio: ["pipe", "pipe", "pipe"],
      });
      tar.stdout.on("data", (c: Buffer) => chunks.push(c));
      tar.stderr.on("data", (c: Buffer) => (stderr += c.toString()));
      tar.on("error", reject);
      tar.on("close", onDone);
      tar.stdin.write(filtered);
      tar.stdin.end();
    } else {
      // Same belt-and-suspenders pairing as the git branch above. Here
      // `-C` already runs before `.` so the initial cwd never mattered
      // for production — adding `cwd` doesn't change anything but keeps
      // the two branches symmetric. Absolute paths everywhere (see
      // absSourceDir comment above) so relative sourceDirs don't
      // double-apply.
      const tar = spawn("tar", ["-czf", "-", ...excludes, "-C", absSourceDir, "."], {
        cwd: absSourceDir,
        stdio: ["ignore", "pipe", "pipe"],
      });
      tar.stdout.on("data", (c: Buffer) => chunks.push(c));
      tar.stderr.on("data", (c: Buffer) => (stderr += c.toString()));
      tar.on("error", reject);
      tar.on("close", onDone);
    }
  });
}

/**
 * Upload a tarball buffer to a path on the sandbox.
 * writeFiles accepts a single Uint8Array; for very large buffers the SDK
 * handles chunking internally.
 */
export async function uploadTarballToSandbox(
  sandbox: Sandbox,
  remoteTarPath: string,
  buffer: Buffer,
  onLog?: (msg: string) => void,
): Promise<void> {
  const mb = (buffer.length / 1024 / 1024).toFixed(1);
  onLog?.(`Uploading ${remoteTarPath} (${mb}MB)...`);
  const started = Date.now();
  await sandbox.writeFiles([{ path: remoteTarPath, content: buffer }]);
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

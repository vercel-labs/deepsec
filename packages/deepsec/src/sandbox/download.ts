import fs from "node:fs";
import path from "node:path";
import { dataDir } from "@deepsec/core";
import type { Sandbox } from "@vercel/sandbox";
import * as tar from "tar";
import { mergeAfterExtract, snapshotFileRecords } from "./merge-records.js";
import { DATA_DIR } from "./setup.js";
import type { SandboxSubcommand } from "./types.js";

// Sandbox results are JSON file records, run metadata, and reports —
// nothing else. Lock the extract to these extensions so a tampered or
// buggy tarball can't smuggle anything else onto the host. If the
// sandbox legitimately needs to return a new file type, add it here.
const ALLOWED_EXTENSIONS = new Set([".json", ".md", ".csv"]);

// Namespace allowlist applied to every entry path inside the per-project
// tarball. The sandbox is the explicit trust boundary — even if someone
// tampered with the archive, the extracted files can only land in these
// known shapes. Critically, this rejects a top-level `project.json` (whose
// `rootPath` field would otherwise be trusted by the next CLI run and steer
// later sandbox uploads at attacker-chosen host paths). See the
// "archive-extraction-untrusted" finding in .deepsec/findings.
//
// Path segments use `[^/\\\0]+` rather than a stricter character class so
// real-world repo paths pass through unchanged: Next.js dynamic routes
// (`[id]`, `[...slug]`, `[[...slug]]`), parallel routes (`@modal`), route
// groups (`(public)`), and filenames with `+`, `=`, `,`, parens, spaces,
// etc. were rejected by the previous `[A-Za-z0-9._-]` class. The defense
// against unsafe segments (`..`, `.`, empty) is now a dedicated check
// below; tar.strict provides the same guarantee for absolute paths and
// `..` traversal as a second layer.
const ALLOWED_ENTRY_PATTERNS: RegExp[] = [
  /^\.?\/?files\/(?:[^/\\\0]+\/)*[^/\\\0]+\.json$/,
  /^\.?\/?runs\/[^/\\\0]+\.json$/,
  /^\.?\/?reports\/report[^/\\\0]*\.(?:json|md|csv)$/,
];

// Belt-and-suspenders caps on a sandbox-supplied tarball. The numbers err
// generous — a real-world per-project results dump for the largest project
// we've shipped is ~30 MB uncompressed, ~5k entries — but they fence off
// decompression bombs and silly entry counts.
const MAX_TARBALL_BYTES = 256 * 1024 * 1024; // 256 MiB compressed
const MAX_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024; // 1 GiB total
const MAX_ENTRIES = 50_000;
const MAX_PER_FILE_BYTES = 32 * 1024 * 1024; // 32 MiB per record

const SETUP_MARKER = "/tmp/deepsec-setup-done";
const downloadLocks = new Map<string, Promise<void>>();

function shellQuote(s: string): string {
  return `'${s.replaceAll("'", "'\\''")}'`;
}

function ensurePlainDirectory(dir: string): void {
  const parent = path.dirname(dir);
  if (parent !== dir && !fs.existsSync(parent)) ensurePlainDirectory(parent);
  try {
    const st = fs.lstatSync(dir);
    if (st.isSymbolicLink()) throw new Error(`Refusing to use symlinked data directory: ${dir}`);
    if (!st.isDirectory()) throw new Error(`Refusing to use non-directory data path: ${dir}`);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    fs.mkdirSync(dir);
  }
}

async function withDownloadLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const prior = downloadLocks.get(key) ?? Promise.resolve();
  let release!: () => void;
  const current = new Promise<void>((resolve) => {
    release = resolve;
  });
  const chained = prior.then(() => current);
  downloadLocks.set(key, chained);
  await prior;
  try {
    return await fn();
  } finally {
    release();
    if (downloadLocks.get(key) === chained) downloadLocks.delete(key);
  }
}

/**
 * Touch a marker file at the end of setup. The results download uses
 * `find -newer <marker>` to grab only files modified during the run.
 */
export async function markSetupComplete(sandbox: Sandbox): Promise<void> {
  const res = await sandbox.runCommand({
    cmd: "touch",
    args: [SETUP_MARKER],
  });
  if (res.exitCode !== 0) {
    throw new Error(`touch ${SETUP_MARKER} failed (exit ${res.exitCode})`);
  }
}

/**
 * Tar up files under `data/<projectId>/` modified since setup, download the
 * tar, and extract it into the local data directory.
 * Returns the number of files extracted.
 *
 * When `advanceMarker` is true, the setup marker is bumped to "now" after
 * a successful download so subsequent polls only pick up newer changes.
 * Use it for streaming downloads mid-run; pass false for the final download
 * so we don't lose anything that lands during the download itself.
 */
export async function downloadResults(
  sandbox: Sandbox,
  sandboxIndex: number,
  projectId: string,
  onLog: (msg: string) => void,
  opts: {
    advanceMarker?: boolean;
    quiet?: boolean;
    allowedFiles?: string[];
    command?: SandboxSubcommand;
  } = {},
): Promise<number> {
  const remoteProjectDir = `${DATA_DIR}/${projectId}`;
  const remoteTarPath = `/tmp/deepsec-results-${sandboxIndex}.tar.gz`;
  const log = (msg: string) => {
    if (!opts.quiet) onLog(msg);
  };

  log(`[sandbox-${sandboxIndex}] Packaging modified files...`);

  // Build the tar of files newer than the setup marker.
  // Cannot use $(find -print0) — bash command substitution strips NUL bytes.
  // Instead detect emptiness separately, then pipe find directly to tar.
  const cutoffMarker = `/tmp/deepsec-sync-cutoff-${sandboxIndex}-${Date.now()}`;
  if (opts.advanceMarker) {
    const touchCutoff = await sandbox.runCommand({ cmd: "touch", args: [cutoffMarker] });
    if (touchCutoff.exitCode !== 0) {
      throw new Error(`[sandbox-${sandboxIndex}] touch ${cutoffMarker} failed`);
    }
  }
  const newerExpr = opts.advanceMarker
    ? `-newer ${shellQuote(SETUP_MARKER)} ! -newer ${shellQuote(cutoffMarker)}`
    : `-newer ${shellQuote(SETUP_MARKER)}`;
  const tarCmd = [
    "sh",
    "-c",
    `cd ${shellQuote(remoteProjectDir)} && ` +
      `first=$(find . ${newerExpr} -type f -print -quit); ` +
      `if [ -z "$first" ]; then echo "__NO_CHANGES__"; exit 0; fi; ` +
      `find . ${newerExpr} -type f -print0 | ` +
      `tar -czf ${shellQuote(remoteTarPath)} --null -T -`,
  ];

  const tarResult = await sandbox.runCommand({
    cmd: tarCmd[0],
    args: tarCmd.slice(1),
  });
  if (tarResult.exitCode !== 0) {
    const err = await tarResult.stderr();
    throw new Error(
      `[sandbox-${sandboxIndex}] tar failed (exit ${tarResult.exitCode}): ${err.slice(0, 500)}`,
    );
  }

  const tarStdout = await tarResult.stdout();
  if (tarStdout.includes("__NO_CHANGES__")) {
    log(`[sandbox-${sandboxIndex}] No changes to download.`);
    if (opts.advanceMarker) {
      await sandbox.runCommand({ cmd: "mv", args: [cutoffMarker, SETUP_MARKER] });
    }
    return 0;
  }

  // Download the tarball
  const localTarPath = `/tmp/deepsec-results-${sandboxIndex}-${Date.now()}.tar.gz`;
  log(`[sandbox-${sandboxIndex}] Downloading results...`);
  const started = Date.now();
  const written = await sandbox.downloadFile(
    { path: remoteTarPath },
    { path: localTarPath },
    { mkdirRecursive: true },
  );
  if (!written) {
    throw new Error(`[sandbox-${sandboxIndex}] downloadFile returned null (source missing?)`);
  }
  const size = fs.statSync(localTarPath).size;
  const mb = (size / 1024 / 1024).toFixed(1);
  log(
    `[sandbox-${sandboxIndex}] Downloaded ${mb}MB in ${((Date.now() - started) / 1000).toFixed(1)}s`,
  );
  if (size > MAX_TARBALL_BYTES) {
    try {
      fs.unlinkSync(localTarPath);
    } catch {}
    throw new Error(
      `Refusing sandbox results tarball: ${mb}MB compressed exceeds ${(MAX_TARBALL_BYTES / 1024 / 1024).toFixed(0)}MB cap.`,
    );
  }

  // Extract locally into data/<projectId>/
  const localProjectDir = dataDir(projectId);
  ensurePlainDirectory(localProjectDir);

  try {
    const count = await withDownloadLock(localProjectDir, () =>
      extractTarballLocally(localTarPath, localProjectDir, {
        allowedFiles: opts.allowedFiles,
        command: opts.command,
      }),
    );
    log(
      `[sandbox-${sandboxIndex}] Extracted ${count} files into ${path.relative(process.cwd(), localProjectDir)}`,
    );

    // Bump the marker after a successful sync so subsequent polls are deltas.
    if (opts.advanceMarker) {
      await sandbox.runCommand({ cmd: "mv", args: [cutoffMarker, SETUP_MARKER] });
    }
    return count;
  } finally {
    try {
      fs.unlinkSync(localTarPath);
    } catch {}
  }
}

export async function extractTarballLocally(
  tarPath: string,
  destDir: string,
  optsOrAllowedFiles?: string[] | { allowedFiles?: string[]; command?: SandboxSubcommand },
): Promise<number> {
  // Two-pass: list to validate, then extract. The list pass is hard
  // "all or nothing" — if any entry is disallowed (wrong type or
  // extension), we throw before a single byte hits disk, so callers
  // never see a half-populated destDir on rejection. Cost is reading
  // the gzip stream twice; sandbox-result tarballs are small, so this
  // is negligible vs. the upload/download time.
  //
  // `strict: true` upgrades parser warnings (absolute paths, `..`
  // segments, malformed pax headers) into thrown errors, so the list
  // pass also catches anything tar's own safety would otherwise just
  // log-and-skip. The extract pass runs with default safety; we know
  // the archive is clean by then.
  const violations: string[] = [];
  const opts = Array.isArray(optsOrAllowedFiles)
    ? { allowedFiles: optsOrAllowedFiles }
    : (optsOrAllowedFiles ?? {});
  const command = opts.command;
  const restrictReturnedNamespaces = command !== undefined;
  const allowRunMetadata = !restrictReturnedNamespaces || command === "scan";
  const allowReports = !restrictReturnedNamespaces || command === "report";
  const allowedFileEntries = opts.allowedFiles
    ? new Set(opts.allowedFiles.map((p) => `files/${p.replaceAll("\\", "/")}.json`))
    : undefined;
  let fileCount = 0;
  let totalUncompressed = 0;
  await tar.list({
    file: tarPath,
    strict: true,
    onentry: (entry) => {
      if (entry.type === "Directory") return;
      if (entry.type !== "File") {
        violations.push(`"${entry.path}" has type ${entry.type}`);
        return;
      }
      const ext = path.extname(entry.path).toLowerCase();
      if (!ALLOWED_EXTENSIONS.has(ext)) {
        violations.push(`"${entry.path}" has extension ${ext || "(none)"}`);
        return;
      }
      const norm = entry.path.replace(/^\.\//, "");
      // Defense-in-depth segment check. tar.strict already rejects `..`
      // segments and absolute paths — this is the second layer in case
      // strictness is ever loosened, plus it explicitly excludes the
      // empty segment / lone "." segment cases we'd otherwise let pass
      // since the allowed-pattern char class is now intentionally broad
      // (to accept Next.js bracket routes, etc.).
      const segments = norm.split("/");
      if (segments.some((s) => s === "" || s === "." || s === "..")) {
        violations.push(`"${entry.path}" has an unsafe path segment`);
        return;
      }
      if (!ALLOWED_ENTRY_PATTERNS.some((re) => re.test(norm))) {
        violations.push(`"${entry.path}" is outside files/, runs/, reports/`);
        return;
      }
      if (norm.startsWith("runs/") && !allowRunMetadata) {
        violations.push(`"${entry.path}" is run metadata not returned by ${command}`);
        return;
      }
      if (norm.startsWith("reports/") && !allowReports) {
        violations.push(`"${entry.path}" is a report artifact not returned by ${command}`);
        return;
      }
      if (allowedFileEntries && norm.startsWith("files/") && !allowedFileEntries.has(norm)) {
        violations.push(`"${entry.path}" is outside this sandbox's manifest`);
        return;
      }
      const sz = (entry as unknown as { size?: number }).size ?? 0;
      if (sz > MAX_PER_FILE_BYTES) {
        violations.push(
          `"${entry.path}" is ${(sz / 1024 / 1024).toFixed(1)}MB > per-file cap ${(MAX_PER_FILE_BYTES / 1024 / 1024).toFixed(0)}MB`,
        );
        return;
      }
      totalUncompressed += sz;
      fileCount++;
      if (fileCount > MAX_ENTRIES) {
        violations.push(`entry count exceeds cap of ${MAX_ENTRIES}`);
      }
      if (totalUncompressed > MAX_UNCOMPRESSED_BYTES) {
        violations.push(
          `uncompressed size exceeds cap of ${(MAX_UNCOMPRESSED_BYTES / 1024 / 1024).toFixed(0)}MB`,
        );
      }
    },
  });
  if (violations.length > 0) {
    const preview = violations.slice(0, 5).join("\n  ");
    const more = violations.length > 5 ? `\n  …and ${violations.length - 5} more` : "";
    throw new Error(
      `Refusing sandbox results tarball: ${violations.length} disallowed entr${violations.length === 1 ? "y" : "ies"}:\n  ${preview}${more}\nAllowed: regular ${[...ALLOWED_EXTENSIONS].sort().join("/")} files under files/, runs/, or reports/; ≤${MAX_ENTRIES} entries, ≤${(MAX_UNCOMPRESSED_BYTES / 1024 / 1024).toFixed(0)}MB total.`,
    );
  }

  // Snapshot existing per-file records BEFORE extracting. The tarball
  // extract is a blind overwrite, so without this any prior on-host
  // analysisHistory / findings / revalidation / triage entries would
  // disappear when a concurrently-running sandbox uploads its (older)
  // view of the same file. We re-merge after extract.
  const hostSnapshot = snapshotFileRecords(destDir);
  await tar.extract({ file: tarPath, cwd: destDir });
  mergeAfterExtract(destDir, hostSnapshot, path.basename(destDir));
  return fileCount;
}

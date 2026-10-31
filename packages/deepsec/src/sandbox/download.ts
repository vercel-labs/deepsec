import fs from "node:fs";
import path from "node:path";
import { dataDir } from "@deepsec/core";
import type { Sandbox } from "@vercel/sandbox";
import * as tar from "tar";
import { isFileRecordPath, mergeAfterExtract, snapshotFileRecords } from "./merge-records.js";
import { DATA_DIR } from "./setup.js";

// Sandbox results are JSON file records, run metadata, reports, and
// debug dumps — nothing else. Lock the extract to these extensions so a
// tampered or buggy tarball can't smuggle anything else onto the host.
// If the sandbox legitimately needs to return a new file type, add it
// here. `.txt` is for parse-failure debug dumps (see
// `writeParseFailureDebug` in the processor); the agent's raw response
// that failed JSON parsing is preserved verbatim and isn't guaranteed
// to be valid JSON, hence a separate extension.
const ALLOWED_EXTENSIONS = new Set([".json", ".md", ".csv", ".txt"]);

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
  // Parse-failure dumps from the processor: a flat directory containing
  // `parse-error-<phase>-<timestamp>.txt` files. Names use only safe
  // characters (the timestamp is an ISO string with `:`/`.` replaced by
  // `-`), but the allowlist character class matches the same broad shape
  // as the files/ pattern so future debug filenames don't get rejected.
  /^\.?\/?debug\/[^/\\\0]+\.txt$/,
  // Revalidation invocation artifacts: raw model responses +
  // reconciliation diagnostics per agent call, one directory per run
  // (`revalidation/<runId>/invocation-NNN.json`). Written by the
  // processor's revalidate(); needed on the host to diagnose/rescore
  // verdict mismatches from sandbox runs.
  /^\.?\/?revalidation\/[^/\\\0]+\/[^/\\\0]+\.json$/,
];

// Belt-and-suspenders caps on a sandbox-supplied tarball. The numbers err
// generous — a real-world per-project results dump for the largest project
// we've shipped is ~30 MB uncompressed, ~5k entries — but they fence off
// decompression bombs and silly entry counts.
const MAX_TARBALL_BYTES = 256 * 1024 * 1024; // 256 MiB compressed
const MAX_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024; // 1 GiB total
const MAX_ENTRIES = 50_000;
// Per-file size is a soft cap: oversized entries are skipped during
// extraction (and reported) rather than failing the whole tarball, since a
// single fat record — e.g. for a large compiled bundle — shouldn't discard
// every other result from the run. The other caps stay hard/all-or-nothing:
// they defend against decompression bombs and smuggled content.
const MAX_PER_FILE_BYTES = 64 * 1024 * 1024; // 64 MiB per record

const SETUP_MARKER = "/tmp/deepsec-setup-done";

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
  opts: { advanceMarker?: boolean; quiet?: boolean } = {},
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
  const tarCmd = [
    "sh",
    "-c",
    `cd ${remoteProjectDir} && ` +
      `first=$(find . -newer ${SETUP_MARKER} -type f -print -quit); ` +
      `if [ -z "$first" ]; then echo "__NO_CHANGES__"; exit 0; fi; ` +
      `find . -newer ${SETUP_MARKER} -type f -print0 | tar -czf ${remoteTarPath} --null -T -`,
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
      await sandbox.runCommand({ cmd: "touch", args: [SETUP_MARKER] });
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
  fs.mkdirSync(localProjectDir, { recursive: true });

  const count = await extractTarballLocally(localTarPath, localProjectDir, (entryPath, bytes) => {
    onLog(
      `[sandbox-${sandboxIndex}] Skipped oversized result file "${entryPath}" (${(bytes / 1024 / 1024).toFixed(1)}MB > ${(MAX_PER_FILE_BYTES / 1024 / 1024).toFixed(0)}MB cap)`,
    );
  });
  try {
    fs.unlinkSync(localTarPath);
  } catch {}
  log(
    `[sandbox-${sandboxIndex}] Extracted ${count} files into ${path.relative(process.cwd(), localProjectDir)}`,
  );

  // Bump the marker after a successful sync so subsequent polls are deltas.
  if (opts.advanceMarker) {
    await sandbox.runCommand({ cmd: "touch", args: [SETUP_MARKER] });
  }
  return count;
}

// Serializes snapshot → extract → merge per destination directory. All 30
// sandbox download loops extract into the same data dir; overlapping
// sequences would (a) stack pre-extract snapshots in memory and (b) race
// each other's read-modify-write of shared records, resurrecting stale
// versions. Extracts are cheap once snapshots are tarball-scoped, so a
// plain promise-chain mutex costs nothing in throughput.
const extractLocks = new Map<string, Promise<void>>();

async function withExtractLock<T>(destDir: string, fn: () => Promise<T>): Promise<T> {
  const key = path.resolve(destDir);
  const prev = extractLocks.get(key) ?? Promise.resolve();
  let release!: () => void;
  const gate = new Promise<void>((r) => {
    release = r;
  });
  const tail = prev.then(() => gate);
  extractLocks.set(key, tail);
  await prev;
  try {
    return await fn();
  } finally {
    release();
    if (extractLocks.get(key) === tail) extractLocks.delete(key);
  }
}

export async function extractTarballLocally(
  tarPath: string,
  destDir: string,
  onSkip?: (entryPath: string, sizeBytes: number) => void,
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
  const entryPaths: string[] = [];
  const oversized = new Map<string, number>();
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
        violations.push(`"${entry.path}" is outside files/, runs/, reports/, revalidation/`);
        return;
      }
      const sz = (entry as unknown as { size?: number }).size ?? 0;
      // Count oversized entries toward the total-size bomb defense even
      // though we skip them: the archive still streams through the
      // extractor either way.
      totalUncompressed += sz;
      if (sz > MAX_PER_FILE_BYTES) {
        oversized.set(norm, sz);
        return;
      }
      fileCount++;
      entryPaths.push(norm);
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
      `Refusing sandbox results tarball: ${violations.length} disallowed entr${violations.length === 1 ? "y" : "ies"}:\n  ${preview}${more}\nAllowed: regular ${[...ALLOWED_EXTENSIONS].sort().join("/")} files under files/, runs/, reports/, debug/, or revalidation/; ≤${MAX_ENTRIES} entries, ≤${(MAX_UNCOMPRESSED_BYTES / 1024 / 1024).toFixed(0)}MB total.`,
    );
  }

  // Snapshot the per-file records this tarball is about to overwrite
  // BEFORE extracting. The tarball extract is a blind overwrite, so
  // without this any prior on-host analysisHistory / findings /
  // revalidation / triage entries would disappear when a
  // concurrently-running sandbox uploads its (older) view of the same
  // file. We re-merge after extract. Snapshot and merge are scoped to the
  // tarball's own entry list, and the whole read-modify-write sequence is
  // serialized per destDir — see withExtractLock.
  for (const [entryPath, sizeBytes] of oversized) {
    onSkip?.(entryPath, sizeBytes);
  }

  const recordPaths = entryPaths.filter(isFileRecordPath);
  await withExtractLock(destDir, async () => {
    const hostSnapshot = snapshotFileRecords(destDir, recordPaths);
    await tar.extract({
      file: tarPath,
      cwd: destDir,
      filter: (entryPath) => !oversized.has(entryPath.replace(/^\.\//, "")),
    });
    mergeAfterExtract(destDir, hostSnapshot, path.basename(destDir), recordPaths);
  });
  return fileCount;
}

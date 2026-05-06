import fs from "node:fs";
import path from "node:path";
import { dataDir } from "@deepsec/core";
import type { Sandbox } from "@vercel/sandbox";
import * as tar from "tar";
import { DATA_DIR } from "./setup.js";

// Sandbox results are JSON file records, run metadata, and reports —
// nothing else. Lock the extract to these extensions so a tampered or
// buggy tarball can't smuggle anything else onto the host. If the
// sandbox legitimately needs to return a new file type, add it here.
const ALLOWED_EXTENSIONS = new Set([".json", ".md", ".csv"]);

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

  // Extract locally into data/<projectId>/
  const localProjectDir = dataDir(projectId);
  fs.mkdirSync(localProjectDir, { recursive: true });

  const count = await extractTarballLocally(localTarPath, localProjectDir);
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

export async function extractTarballLocally(tarPath: string, destDir: string): Promise<number> {
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
  let fileCount = 0;
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
      fileCount++;
    },
  });
  if (violations.length > 0) {
    const preview = violations.slice(0, 5).join("\n  ");
    const more = violations.length > 5 ? `\n  …and ${violations.length - 5} more` : "";
    throw new Error(
      `Refusing sandbox results tarball: ${violations.length} disallowed entr${violations.length === 1 ? "y" : "ies"}:\n  ${preview}${more}\nAllowed: regular files with extensions ${[...ALLOWED_EXTENSIONS].sort().join(", ")}.`,
    );
  }
  await tar.extract({ file: tarPath, cwd: destDir });
  return fileCount;
}

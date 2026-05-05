import fs from "node:fs";
import path from "node:path";
import { dataDir } from "@deepsec/core";
import type { Sandbox } from "@vercel/sandbox";
import { DATA_DIR } from "./setup.js";

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

// The tarball is produced inside the Vercel Sandbox VM, which the README
// threat model explicitly treats as untrusted (prompt-injected agents can
// run shell commands there). A previous `tar -xzvf` shell-out followed
// pre-existing symlinks during extraction, turning sandbox-side code
// execution into orchestrator-host arbitrary file write
// (CVE-2007-4131 / CVE-2018-20482 class). Switch to node-tar, which:
//   - strips absolute paths and `..` components by default
//   - refuses to extract symlinks pointing outside cwd
//   - opens regular files with O_NOFOLLOW under the hood
// The explicit `filter` below additionally rejects symlink AND hardlink
// members entirely — the agent only ever writes regular FileRecord JSON,
// so anything else in the archive is by definition adversarial.
async function extractTarballLocally(tarPath: string, destDir: string): Promise<number> {
  const tar = await loadTar();
  let extracted = 0;
  await tar.extract({
    file: tarPath,
    cwd: destDir,
    filter: (_p, entry) => {
      const t = (entry as { type?: string }).type;
      if (t === "SymbolicLink" || t === "Link") {
        throw new Error(`refusing to extract: tarball contains ${t} member`);
      }
      return true;
    },
    onentry: (entry: { type?: string }) => {
      if (entry.type === "File") extracted++;
    },
  });
  return extracted;
}

// node-tar is a declared dependency; keep it external in the bundle so
// `import("tar")` resolves from the installed package at runtime (pnpm, npm,
// or global installs; no reliance on node_modules/.pnpm layout).
let cachedTar: TarModule | undefined;

interface TarExtractOptions {
  file: string;
  cwd: string;
  filter?: (path: string, entry: unknown) => boolean;
  onentry?: (entry: { type?: string }) => void;
}

interface TarModule {
  extract: (opts: TarExtractOptions) => Promise<void>;
}

async function loadTar(): Promise<TarModule> {
  if (cachedTar) return cachedTar;
  const mod = (await import("tar")) as TarModule;
  cachedTar = mod;
  return mod;
}

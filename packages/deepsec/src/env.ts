import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { config as dotenvConfig } from "dotenv";

function isTrackedByNearestGitRepo(filePath: string, cwd: string): boolean {
  const root = spawnSync("git", ["rev-parse", "--show-toplevel"], {
    cwd,
    encoding: "utf-8",
    stdio: ["ignore", "pipe", "ignore"],
    timeout: 5_000,
  });
  if (root.status !== 0) return false;

  const gitRootRaw = root.stdout.trim();
  if (!gitRootRaw) return false;
  const gitRoot = fs.realpathSync(gitRootRaw);
  const fileAbs = fs.realpathSync(filePath);
  const rel = path.relative(gitRoot, fileAbs).replaceAll("\\", "/");
  if (rel.startsWith("../") || rel === ".." || path.isAbsolute(rel)) return false;

  const tracked = spawnSync("git", ["ls-files", "--error-unmatch", "--", rel], {
    cwd: gitRoot,
    encoding: "utf-8",
    stdio: ["ignore", "ignore", "ignore"],
    timeout: 5_000,
  });
  return tracked.status === 0;
}

/**
 * Load operator-controlled env files only.
 *
 * `.env` is deliberately not loaded: in PR checkouts it is repo-controlled
 * source, so it can redirect provider base URLs or inject child-process
 * execution knobs before real AI credentials are expanded.
 */
export function loadTrustedEnvFiles(cwd: string = process.cwd()): string[] {
  if (process.env.DEEPSEC_SKIP_DOTENV === "1") return [];

  const explicit = process.env.DEEPSEC_ENV_FILE;
  if (explicit) {
    const p = path.resolve(cwd, explicit);
    dotenvConfig({ path: p });
    return [p];
  }

  const envLocal = path.resolve(cwd, ".env.local");
  if (!fs.existsSync(envLocal)) return [];

  try {
    if (fs.lstatSync(envLocal).isSymbolicLink()) {
      console.warn(
        `[deepsec] refusing to load symlinked env file ${path.relative(cwd, envLocal) || envLocal}. ` +
          `Move secrets to a regular ignored .env.local or set DEEPSEC_ENV_FILE explicitly.`,
      );
      return [];
    }
  } catch {
    return [];
  }

  if (isTrackedByNearestGitRepo(envLocal, cwd)) {
    console.warn(
      `[deepsec] refusing to load tracked env file ${path.relative(cwd, envLocal) || envLocal}. ` +
        `Move secrets to an ignored .env.local or set DEEPSEC_ENV_FILE explicitly.`,
    );
    return [];
  }

  dotenvConfig({ path: envLocal });
  return [envLocal];
}

import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { createTerminalLineDecoder, packageInstallProgress } from "./output.js";

export type SupportedPackageManager = "pnpm" | "npm";

function commandExists(command: SupportedPackageManager): boolean {
  // A broken package-manager shim can exist on PATH but never return (for
  // example while its global installation is being repaired). Treat that as
  // unavailable so automatic selection can fall back to the other manager.
  const result = spawnSync(command, ["--version"], { stdio: "ignore", timeout: 3_000 });
  return result.status === 0;
}

export function selectPackageManager(
  workspaceDir: string,
  explicit?: SupportedPackageManager,
  isAvailable: (command: SupportedPackageManager) => boolean = commandExists,
): SupportedPackageManager {
  if (explicit) {
    if (!isAvailable(explicit)) {
      throw new Error(`Requested package manager ${explicit} is not available on PATH`);
    }
    return explicit;
  }
  let preferred: SupportedPackageManager | undefined;
  if (fs.existsSync(path.join(workspaceDir, "pnpm-lock.yaml"))) preferred = "pnpm";
  else if (fs.existsSync(path.join(workspaceDir, "package-lock.json"))) preferred = "npm";
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(workspaceDir, "package.json"), "utf8"));
    if (typeof pkg.packageManager === "string" && pkg.packageManager.startsWith("npm@"))
      preferred ??= "npm";
    if (typeof pkg.packageManager === "string" && pkg.packageManager.startsWith("pnpm@"))
      preferred ??= "pnpm";
  } catch {}
  const ua = process.env.npm_config_user_agent ?? "";
  preferred ??= ua.startsWith("npm/") ? "npm" : "pnpm";
  if (isAvailable(preferred)) return preferred;
  const fallback = preferred === "pnpm" ? "npm" : "pnpm";
  if (isAvailable(fallback)) return fallback;
  throw new Error("Deepsec requires pnpm or npm, but neither command is available on PATH");
}

export function probeWorkspaceInstall(workspaceDir: string): {
  ok: boolean;
  version?: string;
  reason?: string;
} {
  const packageFile = path.join(workspaceDir, "node_modules", "deepsec", "package.json");
  if (!fs.existsSync(packageFile)) return { ok: false, reason: "node_modules/deepsec is missing" };
  try {
    const pkg = JSON.parse(fs.readFileSync(packageFile, "utf8"));
    for (const relative of ["dist/cli.mjs", "dist/config.mjs"]) {
      if (!fs.existsSync(path.join(workspaceDir, "node_modules", "deepsec", relative))) {
        return { ok: false, reason: `deepsec/${relative} is missing` };
      }
    }
    return { ok: true, version: String(pkg.version ?? "unknown") };
  } catch (error) {
    return { ok: false, reason: error instanceof Error ? error.message : String(error) };
  }
}

export async function ensureWorkspaceInstall(params: {
  workspaceDir: string;
  packageManager?: SupportedPackageManager;
  skipInstall?: boolean;
  quiet?: boolean;
  force?: boolean;
  onOutput?: (line: string, stream: "stdout" | "stderr") => void;
  onProgress?: (progress: { message: string; current?: number; total?: number }) => void;
}): Promise<{ packageManager: SupportedPackageManager; version: string; installed: boolean }> {
  const workspaceDir = path.resolve(params.workspaceDir);
  const packageManager = selectPackageManager(workspaceDir, params.packageManager);
  const before = probeWorkspaceInstall(workspaceDir);
  if (before.ok && !params.force) {
    return { packageManager, version: before.version!, installed: false };
  }
  if (params.skipInstall) {
    const reason = params.force
      ? "package.json changed and node_modules must be refreshed"
      : before.reason;
    throw new Error(
      `Workspace dependencies are not installed (${reason}).\n` +
        `Run: cd ${workspaceDir} && ${packageManager} install`,
    );
  }
  const installArgs = ["install"];
  if (params.force && before.ok) installArgs.push("--force");
  params.onProgress?.({ message: `Installing dependencies with ${packageManager}` });
  const result = await new Promise<{ status: number | null }>((resolve, reject) => {
    const child = spawn(packageManager, installArgs, {
      cwd: workspaceDir,
      stdio: ["ignore", "pipe", "pipe"],
      env: process.env,
    });
    let expectedPackages: number | undefined;
    const consumeLine = (stream: "stdout" | "stderr", line: string) => {
      params.onOutput?.(line, stream);
      const progress = packageInstallProgress(line, expectedPackages);
      if (!progress) return;
      expectedPackages = progress.expectedPackages ?? expectedPackages;
      if (progress.current !== undefined) {
        params.onProgress?.({
          message: `Installing dependencies with ${packageManager}`,
          current: progress.current,
          total: progress.total,
        });
      }
    };
    const stdout = createTerminalLineDecoder((line) => consumeLine("stdout", line));
    const stderr = createTerminalLineDecoder((line) => consumeLine("stderr", line));
    child.stdout.on("data", (chunk: Buffer) => stdout.write(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.write(chunk));
    child.once("error", reject);
    child.once("close", (status) => {
      stdout.end();
      stderr.end();
      resolve({ status });
    });
  });
  if (result.status !== 0) {
    throw new Error(
      `${packageManager} install failed with exit ${result.status ?? "unknown"}; see the setup log for package-manager output`,
    );
  }
  const after = probeWorkspaceInstall(workspaceDir);
  if (!after.ok) throw new Error(`Install completed but workspace is unusable: ${after.reason}`);
  params.onProgress?.({ message: `Installed deepsec ${after.version}` });
  return { packageManager, version: after.version!, installed: true };
}

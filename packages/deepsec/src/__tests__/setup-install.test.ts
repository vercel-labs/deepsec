import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { probeWorkspaceInstall, selectPackageManager } from "../setup/install.js";

describe("setup package-manager selection", () => {
  it("falls back to npm when a preferred pnpm is unavailable", () => {
    const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-install-"));
    fs.writeFileSync(
      path.join(workspace, "package.json"),
      JSON.stringify({ packageManager: "pnpm@9.15.4" }),
    );
    expect(selectPackageManager(workspace, undefined, (name) => name === "npm")).toBe("npm");
  });

  it("reports an unavailable explicitly selected package manager", () => {
    const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-install-"));
    expect(() => selectPackageManager(workspace, "pnpm", () => false)).toThrow(
      "Requested package manager pnpm is not available on PATH",
    );
  });
});

describe("post-install workspace probe", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  function installedWorkspace(): string {
    const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-install-"));
    const installed = path.join(workspace, "node_modules", "deepsec", "dist");
    fs.mkdirSync(installed, { recursive: true });
    fs.writeFileSync(
      path.join(workspace, "node_modules", "deepsec", "package.json"),
      JSON.stringify({ version: "1.2.3" }),
    );
    fs.writeFileSync(path.join(installed, "cli.mjs"), "");
    fs.writeFileSync(path.join(installed, "config.mjs"), "");
    return workspace;
  }

  // The installer is a child process that just wrote node_modules, so on a
  // non-coherent mount the probe that follows it can still see nothing there
  // and report "workspace is unusable" for a perfectly good install.
  function lagFirstLookup(): void {
    let calls = 0;
    const real = fs.existsSync;
    vi.spyOn(fs, "existsSync").mockImplementation((target) => {
      calls += 1;
      return calls === 1 ? false : real(target);
    });
  }

  it("tolerates a lagging lookup right after the installer exits", () => {
    const workspace = installedWorkspace();
    vi.stubEnv("DEEPSEC_FS_SETTLE_MS", "0");
    lagFirstLookup();
    expect(probeWorkspaceInstall(workspace, { settle: true })).toEqual({
      ok: true,
      version: "1.2.3",
    });
  });

  it("does not wait out a genuinely missing install", () => {
    const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-install-"));
    expect(probeWorkspaceInstall(workspace)).toEqual({
      ok: false,
      reason: "node_modules/deepsec is missing",
    });
  });
});

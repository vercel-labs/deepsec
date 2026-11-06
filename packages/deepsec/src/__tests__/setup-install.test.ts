import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { reconcilePnpmWorkspace, selectPackageManager } from "../setup/install.js";

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

describe("pnpm workspace reconciliation", () => {
  it("disables strict dependency builds in an existing workspace", () => {
    const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-install-"));
    const file = path.join(workspace, "pnpm-workspace.yaml");
    fs.writeFileSync(file, "packages: []\nallowBuilds:\n  protobufjs: set this to true or false");
    reconcilePnpmWorkspace(workspace);
    reconcilePnpmWorkspace(workspace);
    expect(fs.readFileSync(file, "utf8")).toBe(
      "packages: []\nallowBuilds:\n  protobufjs: set this to true or false\nstrictDepBuilds: false\n",
    );
  });

  it("keeps an explicit strictDepBuilds setting", () => {
    const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-install-"));
    const file = path.join(workspace, "pnpm-workspace.yaml");
    fs.writeFileSync(file, "packages: []\nstrictDepBuilds: true\n");
    reconcilePnpmWorkspace(workspace);
    expect(fs.readFileSync(file, "utf8")).toBe("packages: []\nstrictDepBuilds: true\n");
  });
});

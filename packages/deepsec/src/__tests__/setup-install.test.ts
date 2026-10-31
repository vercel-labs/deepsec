import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { selectPackageManager } from "../setup/install.js";

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

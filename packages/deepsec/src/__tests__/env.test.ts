import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { loadTrustedEnvFiles } from "../env.js";

const KEYS = [
  "DEEPSEC_ENV_FILE",
  "DEEPSEC_SKIP_DOTENV",
  "DEEPSEC_TEST_DOTENV_IGNORED",
  "DEEPSEC_TEST_DOTENV_LOCAL",
  "DEEPSEC_TEST_DOTENV_EXPLICIT",
] as const;

describe("loadTrustedEnvFiles", () => {
  let tmp: string;
  let saved: Record<string, string | undefined>;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-env-"));
    saved = {};
    for (const k of KEYS) {
      saved[k] = process.env[k];
      delete process.env[k];
    }
  });

  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    vi.restoreAllMocks();
  });

  it("loads ignored .env.local but deliberately ignores repo .env", () => {
    fs.writeFileSync(path.join(tmp, ".env"), "DEEPSEC_TEST_DOTENV_IGNORED=bad\n");
    fs.writeFileSync(path.join(tmp, ".env.local"), "DEEPSEC_TEST_DOTENV_LOCAL=ok\n");

    expect(loadTrustedEnvFiles(tmp)).toEqual([path.join(tmp, ".env.local")]);
    expect(process.env.DEEPSEC_TEST_DOTENV_LOCAL).toBe("ok");
    expect(process.env.DEEPSEC_TEST_DOTENV_IGNORED).toBeUndefined();
  });

  it("loads an explicit env file only when DEEPSEC_ENV_FILE is set", () => {
    fs.writeFileSync(path.join(tmp, ".env"), "DEEPSEC_TEST_DOTENV_EXPLICIT=ok\n");
    process.env.DEEPSEC_ENV_FILE = ".env";

    expect(loadTrustedEnvFiles(tmp)).toEqual([path.join(tmp, ".env")]);
    expect(process.env.DEEPSEC_TEST_DOTENV_EXPLICIT).toBe("ok");
  });

  it("refuses tracked .env.local files", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    fs.writeFileSync(path.join(tmp, ".env.local"), "DEEPSEC_TEST_DOTENV_LOCAL=bad\n");
    spawnSync("git", ["init", "-q"], { cwd: tmp });
    spawnSync("git", ["add", ".env.local"], { cwd: tmp });

    expect(loadTrustedEnvFiles(tmp)).toEqual([]);
    expect(process.env.DEEPSEC_TEST_DOTENV_LOCAL).toBeUndefined();
    expect(warn.mock.calls.join("\n")).toContain("refusing to load tracked env file");
  });

  it("refuses symlinked implicit .env.local files", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const outside = path.join(tmp, "outside.env");
    fs.writeFileSync(outside, "DEEPSEC_TEST_DOTENV_LOCAL=bad\n");
    fs.symlinkSync(outside, path.join(tmp, ".env.local"));

    expect(loadTrustedEnvFiles(tmp)).toEqual([]);
    expect(process.env.DEEPSEC_TEST_DOTENV_LOCAL).toBeUndefined();
    expect(warn.mock.calls.join("\n")).toContain("refusing to load symlinked env file");
  });
});

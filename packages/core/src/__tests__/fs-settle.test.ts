import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { existsSettled, mkdirSettled, settleBudgetMs, settleFs } from "../fs-settle.js";

/**
 * Docker Desktop / virtiofs bind mounts of a macOS host return from a create
 * syscall before the new entry is visible to path lookup — measured at 1-2ms,
 * and 100% reproducible inside that window. These tests fake that lag, since
 * a real non-coherent mount is not available in CI.
 */
function enoent(target: string): NodeJS.ErrnoException {
  const error: NodeJS.ErrnoException = new Error(
    `ENOENT: no such file or directory, mkdir '${target}'`,
  );
  error.code = "ENOENT";
  return error;
}

const NO_WAIT = { DEEPSEC_FS_SETTLE_MS: "0" };

afterEach(() => {
  vi.restoreAllMocks();
});

describe("fs-settle", () => {
  // The failure that broke `deepsec init` on a mounted host filesystem:
  // recursive mkdir creates the parent, then cannot see it when it looks up
  // the child, and reports `ENOENT: mkdir 'data/<projectId>'` for a path
  // whose parent it just created.
  it("mkdirSettled retries a recursive mkdir that fails on its own fresh parent", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "settle-"));
    const target = path.join(root, "data", "my-project");
    let calls = 0;
    const real = fs.mkdirSync;
    vi.spyOn(fs, "mkdirSync").mockImplementation(((p: string, opts: never) => {
      calls += 1;
      if (calls === 1) throw enoent(p);
      return real(p, opts);
    }) as typeof fs.mkdirSync);
    mkdirSettled(target, NO_WAIT);
    expect(calls).toBe(2);
    expect(fs.existsSync(target)).toBe(true);
  });

  it("mkdirSettled creates the directory when nothing lags", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "settle-"));
    const target = path.join(root, "data", "my-project");
    mkdirSettled(target, NO_WAIT);
    expect(fs.existsSync(target)).toBe(true);
  });

  // A permission error is not a timing problem — retrying just doubles the
  // wait before reporting the same failure.
  it("mkdirSettled rethrows a non-ENOENT error without retrying", () => {
    let calls = 0;
    vi.spyOn(fs, "mkdirSync").mockImplementation((() => {
      calls += 1;
      const error: NodeJS.ErrnoException = new Error("EACCES: permission denied, mkdir '/nope'");
      error.code = "EACCES";
      throw error;
    }) as typeof fs.mkdirSync);
    expect(() => mkdirSettled("/nope/deeper", NO_WAIT)).toThrow(/EACCES/);
    expect(calls).toBe(1);
  });

  it("mkdirSettled surfaces ENOENT when the retry also fails", () => {
    vi.spyOn(fs, "mkdirSync").mockImplementation(((p: string) => {
      throw enoent(p);
    }) as unknown as typeof fs.mkdirSync);
    expect(() => mkdirSettled("/nope/deeper", NO_WAIT)).toThrow(/ENOENT/);
  });

  it("existsSettled re-checks a lagging lookup once", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "settle-"));
    let calls = 0;
    const real = fs.existsSync;
    vi.spyOn(fs, "existsSync").mockImplementation((target) => {
      calls += 1;
      return calls === 1 ? false : real(target);
    });
    expect(existsSettled(dir, NO_WAIT)).toBe(true);
    expect(calls).toBe(2);
  });

  it("existsSettled costs one call when the path is already visible", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "settle-"));
    const spy = vi.spyOn(fs, "existsSync");
    expect(existsSettled(dir, NO_WAIT)).toBe(true);
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it("existsSettled reports a genuinely missing path as missing", () => {
    expect(existsSettled(path.join(os.tmpdir(), "settle-does-not-exist-42"), NO_WAIT)).toBe(false);
  });

  describe("settleFs", () => {
    it("waits the configured time", () => {
      const started = Date.now();
      settleFs({ DEEPSEC_FS_SETTLE_MS: "40" });
      expect(Date.now() - started).toBeGreaterThanOrEqual(35);
    });

    it("returns immediately when the wait is disabled", () => {
      const started = Date.now();
      settleFs(NO_WAIT);
      expect(Date.now() - started).toBeLessThan(20);
    });
  });

  describe("settleBudgetMs", () => {
    it("defaults to 100ms", () => {
      expect(settleBudgetMs({})).toBe(100);
    });

    it("honors DEEPSEC_FS_SETTLE_MS for slower sync backends", () => {
      expect(settleBudgetMs({ DEEPSEC_FS_SETTLE_MS: "500" })).toBe(500);
    });

    it("allows opting out entirely", () => {
      expect(settleBudgetMs(NO_WAIT)).toBe(0);
    });

    it("rejects a nonsense value", () => {
      expect(() => settleBudgetMs({ DEEPSEC_FS_SETTLE_MS: "soon" })).toThrow(/non-negative number/);
    });
  });
});

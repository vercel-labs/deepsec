import { execSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import * as tar from "tar";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { extractTarballLocally } from "../sandbox/download.js";
import { makeTarball } from "../sandbox/upload.js";

describe("makeTarball — symlink filtering (git branch)", () => {
  let tmp: string;
  const createdTars: string[] = [];

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-upload-"));
  });

  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
    for (const p of createdTars.splice(0)) {
      try {
        fs.unlinkSync(p);
      } catch {}
    }
  });

  it("git: skips symlinks while archiving regular files", async () => {
    // `git init` is enough to put makeTarball on the git branch.
    // No commit is required: `git ls-files --others --exclude-standard`
    // reports untracked-not-ignored files, which is what the upload
    // path actually relies on. Avoiding `git commit` also avoids
    // triggering GPG-signing prompts on dev machines that have
    // `commit.gpgsign=true` set globally.
    execSync("git init -q", { cwd: tmp });

    fs.writeFileSync(path.join(tmp, "ok.json"), '{"v":1}');
    fs.symlinkSync("/etc/passwd", path.join(tmp, "evil.link"));

    const stats = await makeTarball(tmp, []);
    createdTars.push(stats.tarPath);
    const entries = await listTarballEntriesFromFile(stats.tarPath);

    expect(entries.some((e) => e.path.endsWith("ok.json") && e.type === "File")).toBe(true);
    expect(entries.some((e) => e.path.includes("evil.link"))).toBe(false);
    expect(entries.some((e) => e.type === "SymbolicLink")).toBe(false);
  });

  it("returns bytes matching the on-disk tarball size", async () => {
    execSync("git init -q", { cwd: tmp });
    fs.writeFileSync(path.join(tmp, "a.json"), "{}");
    const stats = await makeTarball(tmp, []);
    createdTars.push(stats.tarPath);
    expect(fs.statSync(stats.tarPath).size).toBe(stats.bytes);
  });
});

describe("extractTarballLocally — strict allowlist", () => {
  let tarballDir: string;
  let destDir: string;

  beforeEach(() => {
    tarballDir = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-extract-src-"));
    destDir = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-extract-dst-"));
  });

  afterEach(() => {
    fs.rmSync(tarballDir, { recursive: true, force: true });
    fs.rmSync(destDir, { recursive: true, force: true });
  });

  it("accepts a tarball of allowed extensions", async () => {
    const src = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-tar-good-"));
    fs.writeFileSync(path.join(src, "record.json"), '{"v":1}');
    fs.writeFileSync(path.join(src, "report.md"), "# r");
    const stats = await makeTarball(src, []);
    fs.rmSync(src, { recursive: true, force: true });

    const count = await extractTarballLocally(stats.tarPath, destDir);
    fs.unlinkSync(stats.tarPath);
    expect(count).toBe(2);
    expect(fs.existsSync(path.join(destDir, "record.json"))).toBe(true);
    expect(fs.existsSync(path.join(destDir, "report.md"))).toBe(true);
  });

  it("refuses a tarball with a disallowed extension and writes nothing", async () => {
    const src = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-tar-bad-"));
    fs.writeFileSync(path.join(src, "record.json"), '{"v":1}');
    fs.writeFileSync(path.join(src, "secret.txt"), "uh oh");
    const stats = await makeTarball(src, []);
    fs.rmSync(src, { recursive: true, force: true });

    await expect(extractTarballLocally(stats.tarPath, destDir)).rejects.toThrow(/extension/);
    fs.unlinkSync(stats.tarPath);
    // All-or-nothing: even the otherwise-allowed record.json must not land.
    expect(fs.readdirSync(destDir)).toEqual([]);
  });

  it("refuses a tarball containing a symlink entry", async () => {
    // Build a tarball directly via tar.create that intentionally
    // includes a symlink — bypassing makeTarball's own filter — so
    // we exercise the download-side strict filter in isolation.
    const src = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-tar-sym-"));
    fs.writeFileSync(path.join(src, "record.json"), '{"v":1}');
    fs.symlinkSync("/etc/passwd", path.join(src, "leak.json"));
    const tarPath = path.join(tarballDir, "in.tgz");
    await tar.create({ gzip: true, cwd: src, file: tarPath, portable: true }, [
      "record.json",
      "leak.json",
    ]);
    fs.rmSync(src, { recursive: true, force: true });

    await expect(extractTarballLocally(tarPath, destDir)).rejects.toThrow(/SymbolicLink|type/);
  });
});

async function listTarballEntriesFromFile(
  tarPath: string,
): Promise<{ path: string; type: string }[]> {
  const entries: { path: string; type: string }[] = [];
  await tar.list({
    file: tarPath,
    onentry: (e) => entries.push({ path: e.path, type: e.type as string }),
  });
  return entries;
}

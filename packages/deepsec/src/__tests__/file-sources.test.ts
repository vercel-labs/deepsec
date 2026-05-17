import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { resolveFiles } from "../file-sources.js";

const cleanups: Array<() => void> = [];

afterEach(() => {
  for (const c of cleanups.reverse()) c();
  cleanups.length = 0;
});

function tempRepo(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-fs-"));
  cleanups.push(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const args of [
    ["init", "-q"],
    ["config", "user.email", "t@t"],
    ["config", "user.name", "t"],
    ["config", "commit.gpgsign", "false"],
  ]) {
    const r = spawnSync("git", args, { cwd: root, encoding: "utf-8" });
    if (r.status !== 0) throw new Error(`git ${args.join(" ")}: ${r.stderr}`);
  }
  return root;
}

function gitCommit(root: string, msg: string) {
  spawnSync("git", ["add", "-A"], { cwd: root });
  const r = spawnSync("git", ["commit", "-q", "-m", msg], { cwd: root, encoding: "utf-8" });
  if (r.status !== 0) throw new Error(`git commit: ${r.stderr}`);
}

function write(root: string, rel: string, content: string) {
  const abs = path.join(root, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, content);
}

describe("resolveFiles()", () => {
  it("rejects multiple sources", () => {
    expect(() =>
      resolveFiles({
        rootPath: process.cwd(),
        diff: "HEAD",
        files: ["x.ts"],
      }),
    ).toThrow(/Conflicting/);
  });

  it("--diff returns files changed between ref and HEAD", () => {
    const root = tempRepo();
    write(root, "src/keep.ts", "1\n");
    write(root, "src/changed.ts", "1\n");
    gitCommit(root, "init");

    write(root, "src/changed.ts", "2\n");
    write(root, "src/added.ts", "new\n");
    gitCommit(root, "second");

    const { filePaths, sourceLabel } = resolveFiles({ rootPath: root, diff: "HEAD~1" });
    expect(filePaths.sort()).toEqual(["src/added.ts", "src/changed.ts"]);
    expect(sourceLabel).toBe("git-diff:HEAD~1");
  });

  it("--diff rejects ref-like option injection", () => {
    const root = tempRepo();
    write(root, "src/a.ts", "1\n");
    gitCommit(root, "init");

    expect(() => resolveFiles({ rootPath: root, diff: "--output=/tmp/pwn" })).toThrow(
      /Invalid --diff ref/,
    );
  });

  it("filters out IGNORE_DIRS by default", () => {
    const root = tempRepo();
    write(root, "src/real.ts", "1\n");
    write(root, "src/real.test.ts", "1\n");
    write(root, "dist/built.js", "1\n");
    gitCommit(root, "init");

    write(root, "src/real.ts", "2\n");
    write(root, "src/real.test.ts", "2\n");
    write(root, "dist/built.js", "2\n");
    gitCommit(root, "edit");

    const { filePaths } = resolveFiles({ rootPath: root, diff: "HEAD~1" });
    expect(filePaths).toEqual(["src/real.ts"]);
  });

  it("--no-ignore preserves test/dist paths", () => {
    const root = tempRepo();
    write(root, "src/real.test.ts", "1\n");
    gitCommit(root, "init");
    write(root, "src/real.test.ts", "2\n");
    gitCommit(root, "edit");

    const { filePaths } = resolveFiles({ rootPath: root, diff: "HEAD~1", noIgnore: true });
    expect(filePaths).toEqual(["src/real.test.ts"]);
  });

  it("--files accepts an explicit list and drops missing entries", () => {
    const root = tempRepo();
    write(root, "real.ts", "x\n");

    const { filePaths, skipped, sourceLabel } = resolveFiles({
      rootPath: root,
      files: ["real.ts", "ghost.ts"],
    });
    expect(filePaths).toEqual(["real.ts"]);
    expect(skipped).toEqual([{ path: "ghost.ts", reason: "missing" }]);
    expect(sourceLabel).toBe("files:cli");
  });

  it("--files-from reads newline-delimited paths", () => {
    const root = tempRepo();
    write(root, "a.ts", "x\n");
    write(root, "b.ts", "x\n");

    const listPath = path.join(root, "list.txt");
    fs.writeFileSync(listPath, "a.ts\nb.ts\n\n");

    const { filePaths } = resolveFiles({ rootPath: root, filesFrom: listPath });
    expect(filePaths.sort()).toEqual(["a.ts", "b.ts"]);
  });

  it("strips leading ./ and rejects paths outside root", () => {
    const root = tempRepo();
    write(root, "real.ts", "x\n");

    const { filePaths, skipped } = resolveFiles({
      rootPath: root,
      files: ["./real.ts", "../escape.ts"],
    });
    expect(filePaths).toEqual(["real.ts"]);
    expect(skipped).toEqual([{ path: "../escape.ts", reason: "outside root" }]);
  });

  it("drops symlinks and paths whose real target escapes the root", () => {
    const root = tempRepo();
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-outside-"));
    cleanups.push(() => fs.rmSync(outside, { recursive: true, force: true }));
    fs.writeFileSync(path.join(outside, "secret.ts"), "secret\n");
    fs.symlinkSync(path.join(outside, "secret.ts"), path.join(root, "linked.ts"));
    write(root, "real.ts", "x\n");

    const { filePaths, skipped } = resolveFiles({
      rootPath: root,
      files: ["real.ts", "linked.ts"],
      noIgnore: true,
    });
    expect(filePaths).toEqual(["real.ts"]);
    expect(skipped).toEqual([{ path: "linked.ts", reason: "symlink" }]);
  });

  it("preserves git paths with spaces and newlines via NUL-delimited output", () => {
    const root = tempRepo();
    const spacey = "src/ spaced name.ts";
    const newline = "src/line\nbreak.ts";
    write(root, spacey, "1\n");
    write(root, newline, "1\n");
    gitCommit(root, "init");

    write(root, spacey, "2\n");
    write(root, newline, "2\n");
    gitCommit(root, "edit");

    const { filePaths, skipped } = resolveFiles({ rootPath: root, diff: "HEAD~1" });
    expect(filePaths.sort()).toEqual([newline, spacey].sort());
    expect(skipped).toEqual([]);
  });

  it("does not reinterpret POSIX literal backslashes from git as separators", () => {
    const root = tempRepo();
    const literalBackslash = "src\\literal.ts";
    write(root, literalBackslash, "1\n");
    gitCommit(root, "init");
    write(root, literalBackslash, "2\n");
    gitCommit(root, "edit");

    const { filePaths, skipped } = resolveFiles({ rootPath: root, diff: "HEAD~1" });
    expect(filePaths).toEqual([]);
    expect(skipped).toEqual([{ path: literalBackslash, reason: "unsafe path" }]);
  });

  it("dedupes overlapping inputs", () => {
    const root = tempRepo();
    write(root, "x.ts", "1\n");
    const { filePaths } = resolveFiles({ rootPath: root, files: ["x.ts", "x.ts", "./x.ts"] });
    expect(filePaths).toEqual(["x.ts"]);
  });
});

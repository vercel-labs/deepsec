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

  it("filters generated deepsec data records from explicit file lists", () => {
    const root = tempRepo();
    const oldDataRoot = process.env.DEEPSEC_DATA_ROOT;
    process.env.DEEPSEC_DATA_ROOT = path.join(root, "data{prod,dev}");
    cleanups.push(() => {
      if (oldDataRoot === undefined) delete process.env.DEEPSEC_DATA_ROOT;
      else process.env.DEEPSEC_DATA_ROOT = oldDataRoot;
    });

    write(
      root,
      "data{prod,dev}/app/project.json",
      JSON.stringify({
        projectId: "app",
        rootPath: root,
        createdAt: "2026-01-01T00:00:00.000Z",
      }),
    );
    write(root, "data{prod,dev}/app/files/src/generated.ts.json", "{}");
    write(
      root,
      "data{prod,dev}/other/project.json",
      JSON.stringify({
        projectId: "other",
        rootPath: root,
        createdAt: "2026-01-01T00:00:00.000Z",
      }),
    );
    write(root, "data{prod,dev}/other/files/src/generated.ts.json", "{}");
    write(
      root,
      "data/legacy/project.json",
      JSON.stringify({
        projectId: "legacy",
        rootPath: root,
        createdAt: "2026-01-01T00:00:00.000Z",
      }),
    );
    write(root, "data/legacy/files/src/generated.ts.json", "{}");
    write(root, "data/users/project.json", JSON.stringify({ name: "app users" }));
    write(root, "data/users/files/real.ts", "1\n");

    const { filePaths } = resolveFiles({
      rootPath: root,
      files: [
        "data{prod,dev}/app/files/src/generated.ts.json",
        "data{prod,dev}/other/files/src/generated.ts.json",
        "data/legacy/files/src/generated.ts.json",
        "data/users/files/real.ts",
      ],
    });

    expect(filePaths).toEqual(["data/users/files/real.ts"]);
  });

  it("--files accepts an explicit list and drops missing entries", () => {
    const root = tempRepo();
    write(root, "real.ts", "x\n");

    const { filePaths, sourceLabel } = resolveFiles({
      rootPath: root,
      files: ["real.ts", "ghost.ts"],
    });
    expect(filePaths).toEqual(["real.ts"]);
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

    const { filePaths } = resolveFiles({
      rootPath: root,
      files: ["./real.ts", "../escape.ts"],
    });
    expect(filePaths).toEqual(["real.ts"]);
  });

  it("dedupes overlapping inputs", () => {
    const root = tempRepo();
    write(root, "x.ts", "1\n");
    const { filePaths } = resolveFiles({ rootPath: root, files: ["x.ts", "x.ts", "./x.ts"] });
    expect(filePaths).toEqual(["x.ts"]);
  });
});

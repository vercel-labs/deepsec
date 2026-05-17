import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { loadAllFileRecords, readFileRecord, readRunMeta } from "@deepsec/core";
import { afterEach, describe, expect, it } from "vitest";
import { scanFiles } from "../index.js";

let cleanups: Array<() => void> = [];

afterEach(() => {
  for (const c of cleanups.reverse()) c();
  cleanups = [];
});

function makeProject(files: Record<string, string>): { root: string; projectId: string } {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-scanfiles-"));
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-data-"));
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  process.env.DEEPSEC_DATA_ROOT = dataRoot;
  // Generate a unique project id per test so concurrent vitest workers
  // don't trip over each other's data dirs.
  const projectId = `t-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  cleanups.push(() => {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(dataRoot, { recursive: true, force: true });
    delete process.env.DEEPSEC_DATA_ROOT;
  });
  return { root, projectId };
}

describe("scanFiles()", () => {
  it("writes a FileRecord for every listed file, even with zero matches", async () => {
    const { root, projectId } = makeProject({
      "src/no-match.txt": "this is a plain text file with no matchable content\n",
      "src/maybe-hit.ts": "import { something } from './x';\n",
    });

    const result = await scanFiles({
      projectId,
      root,
      filePaths: ["src/no-match.txt", "src/maybe-hit.ts"],
      source: "files:test",
    });

    expect(result.filesScanned).toBe(2);
    expect(result.skippedFiles).toEqual([]);

    const records = loadAllFileRecords(projectId);
    expect(records).toHaveLength(2);
    const paths = records.map((r) => r.filePath).sort();
    expect(paths).toEqual(["src/maybe-hit.ts", "src/no-match.txt"]);

    const noMatch = readFileRecord(projectId, "src/no-match.txt");
    expect(noMatch).not.toBeNull();
    expect(noMatch!.candidates).toEqual([]);
    expect(noMatch!.fileHash.length).toBeGreaterThan(0);
    expect(noMatch!.lastScannedRunId).toBe(result.runId);
  });

  it("records mode='files' + source label in run-meta", async () => {
    const { root, projectId } = makeProject({ "a.js": "const x = 1;\n" });
    const result = await scanFiles({
      projectId,
      root,
      filePaths: ["a.js"],
      source: "git-diff:origin/main",
    });
    const meta = readRunMeta(projectId, result.runId);
    expect(meta.scannerConfig?.mode).toBe("files");
    expect(meta.scannerConfig?.source).toBe("git-diff:origin/main");
    expect(meta.scannerConfig?.fileCount).toBe(1);
  });

  it("skips listed paths that don't exist on disk", async () => {
    const { root, projectId } = makeProject({ "real.ts": "x\n" });
    const result = await scanFiles({
      projectId,
      root,
      filePaths: ["real.ts", "ghost.ts"],
    });
    expect(result.filesScanned).toBe(1);
    expect(result.skippedFiles).toEqual([
      { filePath: "ghost.ts", reason: "unreadable, unsafe, binary, or oversized" },
    ]);
    // The ghost path produces no record.
    const records = loadAllFileRecords(projectId);
    expect(records.map((r) => r.filePath)).toEqual(["real.ts"]);
  });

  it("preserves prior candidates when a file is rescanned", async () => {
    const { root, projectId } = makeProject({
      // Use a pattern that an actual matcher will fire on. SQL injection
      // matchers fire on `"SELECT * FROM users WHERE id = " + req.query.id`.
      "src/x.ts": 'const q = "SELECT * FROM users WHERE id = " + req.query.id;\n',
    });

    await scanFiles({ projectId, root, filePaths: ["src/x.ts"] });
    const before = readFileRecord(projectId, "src/x.ts")!;
    const candCountBefore = before.candidates.length;

    // Re-scan; existing candidates should be preserved (deduped).
    await scanFiles({ projectId, root, filePaths: ["src/x.ts"] });
    const after = readFileRecord(projectId, "src/x.ts")!;
    expect(after.candidates.length).toBe(candCountBefore);
  });
});

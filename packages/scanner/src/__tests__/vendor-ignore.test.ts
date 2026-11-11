import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { loadAllFileRecords } from "@deepsec/core";
import { afterEach, describe, expect, it } from "vitest";
import { scan } from "../index.js";

let cleanups: Array<() => void> = [];

afterEach(() => {
  for (const cleanup of cleanups.reverse()) cleanup();
  cleanups = [];
});

function makeProject(files: Record<string, string>): { root: string; projectId: string } {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-vendor-"));
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

describe("scan() vendor directories", () => {
  it("keeps vendor files out of candidates and language statistics", async () => {
    const { root, projectId } = makeProject({
      "package.json": JSON.stringify({ dependencies: { express: "5.0.0" } }),
      "src/api.ts": 'app.get("/users", (req, res) => res.json({}));\n',
      "vendor/pkg/api.ts": 'app.get("/vendored", (req, res) => res.json({}));\n',
    });

    const result = await scan({
      projectId,
      root,
      matcherSlugs: ["js-express-route"],
    });

    const records = loadAllFileRecords(projectId);
    expect(records.map((record) => record.filePath)).toEqual(["src/api.ts"]);
    expect(result.languageStats).toEqual([
      {
        language: "typescript",
        scannedFiles: 1,
        candidates: 1,
        matchRate: 1,
      },
    ]);
  });
});

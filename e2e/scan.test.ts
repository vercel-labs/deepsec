import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { listRuns, loadAllFileRecords } from "../packages/core/src/index.js";
import { scan } from "../packages/scanner/src/index.js";

const ROOT = path.resolve(import.meta.dirname, "..");
const FIXTURES = path.join(ROOT, "fixtures/vulnerable-app");
const DATA_DIR = path.join(ROOT, "data");
const PROJECT_ID = "e2e-test";

function cleanup() {
  const projectDir = path.join(DATA_DIR, PROJECT_ID);
  if (fs.existsSync(projectDir)) {
    fs.rmSync(projectDir, { recursive: true });
  }
}

describe("scan e2e", () => {
  beforeEach(cleanup);
  afterEach(cleanup);

  it("scans fixture project and creates file records", async () => {
    const result = await scan({
      projectId: PROJECT_ID,
      root: FIXTURES,
    });

    expect(result.runId).toMatch(/^\d{14}-[a-f0-9]{16}$/);
    expect(result.candidateCount).toBeGreaterThanOrEqual(5);

    // Verify project.json exists
    const projectPath = path.join(DATA_DIR, PROJECT_ID, "project.json");
    expect(fs.existsSync(projectPath)).toBe(true);

    // Verify run metadata (flat file)
    const runPath = path.join(DATA_DIR, PROJECT_ID, "runs", result.runId + ".json");
    expect(fs.existsSync(runPath)).toBe(true);
    const runMeta = JSON.parse(fs.readFileSync(runPath, "utf-8"));
    expect(runMeta.type).toBe("scan");
    expect(runMeta.phase).toBe("done");

    // Verify file records exist
    const records = loadAllFileRecords(PROJECT_ID);
    expect(records.length).toBeGreaterThanOrEqual(5);
    expect(records[0].status).toBe("pending");
    expect(records[0].candidates.length).toBeGreaterThan(0);
  });

  it("merges matches on second scan (no duplicates)", async () => {
    await scan({ projectId: PROJECT_ID, root: FIXTURES });
    const recordsBefore = loadAllFileRecords(PROJECT_ID);

    // Scan again
    await scan({ projectId: PROJECT_ID, root: FIXTURES });
    const recordsAfter = loadAllFileRecords(PROJECT_ID);

    // Same number of files — not duplicated
    expect(recordsAfter.length).toBe(recordsBefore.length);

    // Matches should not be duplicated
    for (const after of recordsAfter) {
      const before = recordsBefore.find((r) => r.filePath === after.filePath);
      expect(before).toBeDefined();
      expect(after.candidates.length).toBe(before!.candidates.length);
    }
  });

  it("produces separate run IDs for consecutive scans", async () => {
    const result1 = await scan({ projectId: PROJECT_ID, root: FIXTURES });
    const result2 = await scan({ projectId: PROJECT_ID, root: FIXTURES });
    expect(result1.runId).not.toBe(result2.runId);

    const runs = listRuns(PROJECT_ID);
    expect(runs.length).toBe(2);
  });

  it("supports matcher filter", async () => {
    const result = await scan({
      projectId: PROJECT_ID,
      root: FIXTURES,
      matcherSlugs: ["xss", "rce"],
    });

    const runPath = path.join(DATA_DIR, PROJECT_ID, "runs", result.runId + ".json");
    const meta = JSON.parse(fs.readFileSync(runPath, "utf-8"));
    expect(meta.scannerConfig.matcherSlugs).toEqual(["xss", "rce"]);
  });

  it("does not scan generated deepsec data records", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-scan-root-"));
    const dataRoot = path.join(root, ".deepsec", "data");
    const projectId = "ignore-deepsec-data";
    const oldDataRoot = process.env.DEEPSEC_DATA_ROOT;
    process.env.DEEPSEC_DATA_ROOT = dataRoot;
    try {
      const generatedDir = path.join(root, ".deepsec", "data", "app", "files", "src");
      fs.mkdirSync(generatedDir, { recursive: true });
      fs.writeFileSync(
        path.join(generatedDir, "generated.json"),
        JSON.stringify({
          filePath: "src/generated.ts",
          candidates: [
            {
              snippet: 'const token = "REDACTED" + "generated-output";',
            },
          ],
        }),
      );
      const activeDataDir = path.join(dataRoot, projectId, "files", "src");
      fs.mkdirSync(activeDataDir, { recursive: true });
      fs.writeFileSync(
        path.join(activeDataDir, "generated.ts"),
        'const stripe = "sk_live_" + "activegeneratedaa";\n',
      );
      const rootMirrorDir = path.join(root, "data", "other-project", "files", "src");
      fs.mkdirSync(rootMirrorDir, { recursive: true });
      fs.writeFileSync(
        path.join(root, "data", "other-project", "project.json"),
        JSON.stringify({
          projectId: "other-project",
          rootPath: root,
          createdAt: "2026-01-01T00:00:00.000Z",
        }),
      );
      fs.writeFileSync(
        path.join(rootMirrorDir, "generated.ts"),
        'const stripe = "sk_live_" + "rootmirrorgenerated";\n',
      );
      const siblingDataDir = path.join(dataRoot, "sibling-project", "files", "src");
      fs.mkdirSync(siblingDataDir, { recursive: true });
      fs.writeFileSync(path.join(dataRoot, "sibling-project", "project.json"), "{}");
      fs.writeFileSync(
        path.join(siblingDataDir, "generated.json"),
        JSON.stringify({
          candidates: [{ snippet: 'const token = "REDACTED" + "sibling-output";' }],
        }),
      );
      const realDataDir = path.join(root, "data", "users", "files");
      fs.mkdirSync(realDataDir, { recursive: true });
      fs.writeFileSync(
        path.join(realDataDir, "leak.ts"),
        'const stripe = "sk_live_" + "abcdefghijklmnop";\n',
      );

      const result = await scan({
        projectId,
        root,
        matcherSlugs: ["secrets-exposure"],
      });

      expect(result.candidateCount).toBe(1);
      expect(loadAllFileRecords(projectId).map((r) => r.filePath)).toEqual([
        "data/users/files/leak.ts",
      ]);
    } finally {
      if (oldDataRoot === undefined) delete process.env.DEEPSEC_DATA_ROOT;
      else process.env.DEEPSEC_DATA_ROOT = oldDataRoot;
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

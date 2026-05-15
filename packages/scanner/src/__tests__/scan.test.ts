import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { readFileRecord, writeFileRecord } from "@deepsec/core";
import { afterEach, describe, expect, it } from "vitest";
import { scan } from "../index.js";

let cleanups: Array<() => void> = [];

afterEach(() => {
  for (const c of cleanups.reverse()) c();
  cleanups = [];
});

function makeProject(files: Record<string, string>): { root: string; projectId: string } {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-scan-"));
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-data-"));
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  process.env.DEEPSEC_DATA_ROOT = dataRoot;
  const projectId = `t-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  cleanups.push(() => {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(dataRoot, { recursive: true, force: true });
    delete process.env.DEEPSEC_DATA_ROOT;
  });
  return { root, projectId };
}

describe("scan()", () => {
  it("resets findings and status when file content changes", async () => {
    const { root, projectId } = makeProject({
      "src/x.ts": 'const q = "SELECT * FROM users WHERE id = " + req.query.id;\n',
    });

    await scan({ projectId, root });
    const first = readFileRecord(projectId, "src/x.ts")!;
    expect(first.status).toBe("pending");
    expect(first.candidates.length).toBeGreaterThan(0);

    // Mark as analyzed with a finding
    first.status = "analyzed";
    first.findings = [
      {
        severity: "HIGH",
        vulnSlug: "sql-injection",
        title: "t",
        description: "d",
        lineNumbers: [1],
        recommendation: "r",
        confidence: "high",
      },
    ];
    writeFileRecord(first);

    // Change content
    fs.writeFileSync(path.join(root, "src/x.ts"), "const x = 1;\n");

    await scan({ projectId, root });
    const second = readFileRecord(projectId, "src/x.ts")!;
    expect(second.status).toBe("pending");
    expect(second.findings).toEqual([]);
  });

  it("clears candidates and findings for deleted files", async () => {
    const { root, projectId } = makeProject({
      "src/x.ts": 'const q = "SELECT * FROM users WHERE id = " + req.query.id;\n',
    });

    await scan({ projectId, root });
    const first = readFileRecord(projectId, "src/x.ts")!;
    expect(first.candidates.length).toBeGreaterThan(0);

    // Delete the file
    fs.rmSync(path.join(root, "src/x.ts"));

    await scan({ projectId, root });
    const second = readFileRecord(projectId, "src/x.ts")!;
    expect(second.candidates).toEqual([]);
    expect(second.findings).toEqual([]);
    expect(second.status).toBe("pending");
  });

  it("clears candidates and findings for files that no longer match", async () => {
    const { root, projectId } = makeProject({
      "src/x.ts": 'const q = "SELECT * FROM users WHERE id = " + req.query.id;\n',
    });

    await scan({ projectId, root });
    const first = readFileRecord(projectId, "src/x.ts")!;
    expect(first.candidates.length).toBeGreaterThan(0);

    // Change content so it no longer matches
    fs.writeFileSync(path.join(root, "src/x.ts"), "const x = 1;\n");

    await scan({ projectId, root });
    const second = readFileRecord(projectId, "src/x.ts")!;
    expect(second.candidates).toEqual([]);
    expect(second.findings).toEqual([]);
    expect(second.status).toBe("pending");
  });
});

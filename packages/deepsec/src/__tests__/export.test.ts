import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { dataDir, ensureProject, writeFileRecord } from "@deepsec/core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { exportCommand } from "../commands/export.js";

let cleanup: (() => void) | null = null;

afterEach(() => {
  cleanup?.();
  cleanup = null;
  delete process.env.DEEPSEC_DATA_ROOT;
  vi.restoreAllMocks();
});

function setupProject(): { projectId: string; root: string } {
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-export-"));
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-export-root-"));
  process.env.DEEPSEC_DATA_ROOT = dataRoot;
  cleanup = () => {
    fs.rmSync(dataRoot, { recursive: true, force: true });
    fs.rmSync(root, { recursive: true, force: true });
  };
  const projectId = `x-${Date.now().toString(36)}`;
  ensureProject(projectId, root);
  return { projectId, root };
}

describe("exportCommand()", () => {
  it("builds stable GitHub links for slash branches and empty line arrays", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const { projectId } = setupProject();
    const projectPath = path.join(dataDir(projectId), "project.json");
    const project = JSON.parse(fs.readFileSync(projectPath, "utf-8"));
    project.githubUrl = "https://github.com/acme/repo/blob/feature/security-hardening";
    fs.writeFileSync(projectPath, JSON.stringify(project, null, 2) + "\n");

    writeFileRecord({
      projectId,
      filePath: "src/a.ts",
      candidates: [],
      lastScannedAt: new Date().toISOString(),
      lastScannedRunId: "scan",
      fileHash: "h",
      findings: [
        {
          severity: "HIGH",
          vulnSlug: "xss",
          title: "Unsafe HTML",
          description: "desc",
          lineNumbers: [],
          recommendation: "fix",
          confidence: "high",
        },
      ],
      analysisHistory: [
        {
          runId: "process",
          investigatedAt: new Date().toISOString(),
          durationMs: 1,
          agentType: "stub",
          model: "stub",
          modelConfig: {},
          findingCount: 1,
        },
      ],
      status: "analyzed",
    });

    const out = path.join(path.dirname(projectPath), "export.json");
    await exportCommand({ projectId, format: "json", out });
    const exported = JSON.parse(fs.readFileSync(out, "utf-8"));
    expect(exported[0].metadata.githubUrl).toBe(
      "https://github.com/acme/repo/blob/feature/security-hardening/src/a.ts",
    );
    expect(exported[0].description).toContain("lines n/a");
    expect(exported[0].description).not.toContain("undefined");
  });

  it("sanitizes issue titles while preserving rawTitle metadata", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const { projectId } = setupProject();

    writeFileRecord({
      projectId,
      filePath: "src/a.ts",
      candidates: [],
      lastScannedAt: new Date().toISOString(),
      lastScannedRunId: "scan",
      fileHash: "h",
      findings: [
        {
          severity: "HIGH",
          vulnSlug: "xss",
          title: "\u001b[31m::error::spoof\nnext",
          description: "desc",
          lineNumbers: [1],
          recommendation: "fix",
          confidence: "high",
        },
      ],
      analysisHistory: [
        {
          runId: "process",
          investigatedAt: new Date().toISOString(),
          durationMs: 1,
          agentType: "stub",
          model: "stub",
          modelConfig: {},
          findingCount: 1,
        },
      ],
      status: "analyzed",
    });

    const out = path.join(dataDir(projectId), "export.json");
    await exportCommand({ projectId, format: "json", out });
    const exported = JSON.parse(fs.readFileSync(out, "utf-8"));
    expect(exported[0].title).toBe("[HIGH] : :error::spoof next");
    expect(exported[0].metadata.rawTitle).toBe("\u001b[31m::error::spoof\nnext");
  });

  it("md-dir only removes files owned by its manifest and refuses symlink dirs", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const { projectId } = setupProject();

    writeFileRecord({
      projectId,
      filePath: "src/a.ts",
      candidates: [],
      lastScannedAt: new Date().toISOString(),
      lastScannedRunId: "scan",
      fileHash: "h",
      findings: [
        {
          severity: "HIGH",
          vulnSlug: "xss",
          title: "Unsafe HTML",
          description: "desc",
          lineNumbers: [1],
          recommendation: "fix",
          confidence: "high",
        },
      ],
      analysisHistory: [
        {
          runId: "process",
          investigatedAt: new Date().toISOString(),
          durationMs: 1,
          agentType: "stub",
          model: "stub",
          modelConfig: {},
          findingCount: 1,
        },
      ],
      status: "analyzed",
    });

    const out = path.join(dataDir(projectId), "md-out");
    fs.mkdirSync(path.join(out, "HIGH"), { recursive: true });
    fs.writeFileSync(path.join(out, "HIGH", "user-owned.md"), "keep\n");

    await exportCommand({ projectId, format: "md-dir", out });
    expect(fs.existsSync(path.join(out, "HIGH", "user-owned.md"))).toBe(true);

    fs.rmSync(path.join(out, "HIGH"), { recursive: true, force: true });
    fs.symlinkSync(os.tmpdir(), path.join(out, "HIGH"));
    await expect(exportCommand({ projectId, format: "md-dir", out })).rejects.toThrow(
      /symlinked export directory/,
    );
  });
});

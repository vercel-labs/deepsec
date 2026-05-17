import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ensureProject, reportMdPath, writeFileRecord } from "@deepsec/core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { reportCommand } from "../commands/report.js";

let cleanup: (() => void) | null = null;

afterEach(() => {
  cleanup?.();
  cleanup = null;
  delete process.env.DEEPSEC_DATA_ROOT;
  vi.restoreAllMocks();
});

function setupProject(): { projectId: string; root: string } {
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-report-"));
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-report-root-"));
  process.env.DEEPSEC_DATA_ROOT = dataRoot;
  cleanup = () => {
    fs.rmSync(dataRoot, { recursive: true, force: true });
    fs.rmSync(root, { recursive: true, force: true });
  };
  const projectId = `r-${Date.now().toString(36)}`;
  ensureProject(projectId, root);
  return { projectId, root };
}

describe("reportCommand()", () => {
  it("escapes model-controlled markdown and renders empty line arrays safely", async () => {
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
          title: "@team <img src=x>",
          description: "![leak](https://evil.example/x) @owner",
          lineNumbers: [],
          recommendation: "<script>alert(1)</script>",
          confidence: "high",
          revalidation: {
            verdict: "uncertain",
            reasoning: "<b>@reviewer</b>",
            revalidatedAt: new Date().toISOString(),
            runId: "rv",
            model: "stub",
          },
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
      gitInfo: {
        recentCommitters: [{ name: "@dev <img>", email: "dev@example.com", date: "2026-05-01" }],
        enrichedAt: new Date().toISOString(),
      },
      status: "analyzed",
    });

    await reportCommand({ projectId });
    const md = fs.readFileSync(reportMdPath(projectId), "utf-8");
    expect(md).not.toContain("<img");
    expect(md).not.toContain("<script>");
    expect(md).not.toContain("![leak]");
    expect(md).not.toContain("@owner");
    expect(md).toContain("&#64;owner");
    expect(md).toContain("- **Lines:** n/a");
  });

  it("strips control sequences from stdout finding summaries", async () => {
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((msg?: unknown) => {
      logs.push(String(msg ?? ""));
    });
    const { projectId } = setupProject();

    writeFileRecord({
      projectId,
      filePath: "src/\u001b[31mfile.ts",
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

    await reportCommand({ projectId });
    const stdout = logs.join("\n");
    expect(stdout).not.toContain("\u001b[31m");
    expect(stdout).not.toContain("::error::");
    expect(stdout).toContain(": :error::spoof next");
  });
});

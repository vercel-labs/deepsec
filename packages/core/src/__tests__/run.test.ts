import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import { createRunMeta, ensureProject, generateRunId } from "../run.js";

describe("generateRunId", () => {
  it("returns a string with timestamp and suffix", () => {
    const id = generateRunId();
    expect(id).toMatch(/^\d{14}-[a-f0-9]{16}$/);
  });

  it("generates unique IDs", () => {
    const ids = new Set(Array.from({ length: 20 }, () => generateRunId()));
    expect(ids.size).toBe(20);
  });
});

describe("createRunMeta", () => {
  it("creates a scan RunMeta", () => {
    const meta = createRunMeta({
      projectId: "test-project",
      rootPath: "/tmp/test",
      type: "scan",
      scannerConfig: { matcherSlugs: ["xss", "rce"] },
    });

    expect(meta.projectId).toBe("test-project");
    expect(meta.type).toBe("scan");
    expect(meta.phase).toBe("running");
    expect(meta.scannerConfig?.matcherSlugs).toEqual(["xss", "rce"]);
    expect(meta.stats).toEqual({});
    expect(meta.runId).toMatch(/^\d{14}-[a-f0-9]{16}$/);
  });

  it("creates a process RunMeta", () => {
    const meta = createRunMeta({
      projectId: "test",
      rootPath: "/tmp",
      type: "process",
      processorConfig: {
        agentType: "claude-agent-sdk",
        model: "claude-opus-4-6",
        modelConfig: {},
      },
    });

    expect(meta.type).toBe("process");
    expect(meta.processorConfig?.agentType).toBe("claude-agent-sdk");
  });
});

describe("ensureProject", () => {
  it("does not print git errors for non-git roots", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-ensure-project-"));
    const oldDataRoot = process.env.DEEPSEC_DATA_ROOT;
    process.env.DEEPSEC_DATA_ROOT = path.join(tmp, "data");
    const root = path.join(tmp, "project");
    fs.mkdirSync(root);

    const writeSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    try {
      const project = ensureProject("test-project", root);
      expect(project.githubUrl).toBeUndefined();
      expect(writeSpy.mock.calls.join("")).not.toContain("fatal: not a git repository");
    } finally {
      writeSpy.mockRestore();
      if (oldDataRoot === undefined) {
        delete process.env.DEEPSEC_DATA_ROOT;
      } else {
        process.env.DEEPSEC_DATA_ROOT = oldDataRoot;
      }
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

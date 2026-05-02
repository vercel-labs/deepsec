import { describe, expect, it } from "vitest";
import { createRunMeta, generateRunId } from "../run.js";

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

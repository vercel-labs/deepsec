import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { SetupWorkflowResult } from "../setup/coordinator.js";
import { createSetupRedactor, createSetupReporter, printSetupSummary } from "../setup/reporter.js";

afterEach(() => vi.restoreAllMocks());

describe("setup reporter", () => {
  it("redacts secrets before rendering or persisting events", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-reporter-"));
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const reporter = await createSetupReporter({
      workspaceDir: root,
      projectId: "app",
      noTui: true,
      env: { OPENAI_API_KEY: "sk-super-secret-value" },
    });

    reporter.emit({
      type: "log",
      phase: "install",
      level: "warn",
      message: "provider returned sk-super-secret-value",
    });
    await reporter.close("success");

    expect(warn).toHaveBeenCalledWith("provider returned [REDACTED]");
    const persisted = fs.readFileSync(reporter.logPath!, "utf8");
    expect(persisted).toContain("[REDACTED]");
    expect(persisted).not.toContain("sk-super-secret-value");
  });

  it("redacts bearer tokens, JWTs, and URL passwords", () => {
    const redact = createSetupRedactor({});
    const value = redact(
      "Bearer abcdefghijklmnop eyJhbGciOiJIUzI1NiJ9.cGF5bG9hZA.c2ln https://user:password@example.com/path",
    );
    expect(value).not.toContain("abcdefghijklmnop");
    expect(value).not.toContain("cGF5bG9hZA");
    expect(value).not.toContain("password");
  });

  it("streams redacted JSONL events without human formatting", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-jsonl-reporter-"));
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const reporter = await createSetupReporter({
      workspaceDir: root,
      projectId: "app",
      outputMode: "jsonl",
      env: { OPENAI_API_KEY: "sk-super-secret-value" },
    });
    reporter.emit({
      type: "log",
      phase: "login",
      level: "warn",
      message: "failed with sk-super-secret-value",
    });

    const payload = JSON.parse(String(log.mock.calls[0]?.[0]));
    expect(payload).toMatchObject({
      type: "setup_event",
      event: { type: "log", message: "failed with [REDACTED]" },
    });
  });

  it("renders an explicit machine-readable partial completion", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    printSetupSummary(
      {
        state: { agent: { type: "pi", model: "deepseek/deepseek-v4-flash" } },
        completed: false,
        stoppedAfter: "coverage",
        generatedMatchers: { attempts: 0, accepted: [], rejected: [] },
      } as unknown as SetupWorkflowResult,
      { workspaceDir: "/repo/.deepsec", projectId: "app", outputMode: "json" },
    );

    expect(JSON.parse(String(log.mock.calls[0]?.[0]))).toMatchObject({
      completed: false,
      stoppedAfter: "coverage",
      model: { model: "deepseek/deepseek-v4-flash" },
    });
  });

  it("summarizes the durable process run with severity and cost", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    vi.spyOn(process, "cwd").mockReturnValue("/repo");
    printSetupSummary(
      {
        state: {
          agent: { type: "codex", model: "gpt-5.6-sol", thinkingLevel: "xhigh" },
          connection: {
            project: { teamId: "team_1", projectId: "prj_1" },
            route: { mode: "direct", provider: "openai" },
          },
        },
        coverage: {
          surfaces: [
            {
              passed: true,
              fileCount: 5,
              coveredFileCount: 4,
              representativeFileCount: 2,
              coveredRepresentativeFileCount: 2,
            },
          ],
          candidateFileCount: 4,
          sourceFileCount: 10,
        },
        processRunId: "run-1",
        process: {
          analysisCount: 4,
          findingCount: 2,
          errorBatchCount: 0,
          findingsBySeverity: { HIGH: 1, MEDIUM: 1 },
          costUsd: 0.125,
        },
        generatedMatchers: { attempts: 1, accepted: ["route-auth"], rejected: [] },
      } as unknown as SetupWorkflowResult,
      {
        workspaceDir: "/repo/.deepsec",
        projectId: "app",
        logPath: "/repo/.deepsec/data/app/setup/setup.jsonl",
      },
    );

    const output = log.mock.calls.flat().join("\n");
    expect(output).toContain("\x1b[");
    expect(output).toContain("Deepsec found");
    expect(output).toContain("potential findings");
    expect(output).toContain("Investigated");
    expect(output).toContain(
      "Coverage: 1/1 surfaces · 4/5 surface-file checks · 2/2 representatives",
    );
    expect(output).not.toContain("4/10 source files");
    expect(output).toContain("cd .deepsec");
    expect(output).toContain("pnpm deepsec revalidate");
    expect(output).toContain(
      "pnpm deepsec export --only-true-positive --format md-dir --out ../findings",
    );
    expect(output).toContain("→ ");
    expect(output).toContain("findings/");
    expect(output).toContain(".deepsec/data/app/INFO.md");
    expect(output).not.toContain("/repo/.deepsec");
    expect(output).toContain("gpt-5.6-sol");
    expect(output).toContain("xhigh");
    expect(output).toContain("$0.1250");
  });
});

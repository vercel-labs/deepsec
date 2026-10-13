import { renderToString } from "ink";
import { createElement } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Dashboard, prepareTerminalInput, type TuiSnapshot } from "../setup/tui.js";

afterEach(() => vi.useRealTimers());

describe("setup TUI", () => {
  it("refs and resumes stdin before handing the terminal to readline", () => {
    const input = {
      setRawMode: vi.fn(),
      ref: vi.fn(),
      resume: vi.fn(),
    };

    prepareTerminalInput(input);

    expect(input.setRawMode).toHaveBeenCalledWith(false);
    expect(input.ref).toHaveBeenCalledOnce();
    expect(input.resume).toHaveBeenCalledOnce();
  });

  it("renders phase state, current metrics, and sanitized log lines", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-03T12:02:14Z"));
    const snapshot: TuiSnapshot = {
      projectId: "vercel-sql",
      startedAt: new Date("2026-08-03T12:00:00Z").getTime(),
      phases: {
        install: { status: "complete", durationMs: 7_000 },
        coverage: { status: "running" },
      },
      activePhase: "coverage",
      activeMessage: "matcher attempt 1/2",
      metrics: { "candidate files": 22, "uncovered surfaces": 2 },
      logs: [{ id: 1, level: "info", message: "accepted generated matcher" }],
      logOffset: 0,
      verbose: false,
    };

    const output = renderToString(
      createElement(Dashboard, {
        snapshot,
        onScroll: () => undefined,
        onFollow: () => undefined,
        onVerbose: () => undefined,
      }),
      { columns: 100 },
    );

    expect(output).toContain("deepsec setup · vercel-sql");
    expect(output).toContain("✓ Install");
    expect(output).toContain("● Coverage");
    expect(output).toContain("candidate files: 22");
    expect(output).toContain("accepted generated matcher");
  });

  it("fills the terminal height and expands the log viewport", () => {
    const snapshot: TuiSnapshot = {
      projectId: "tall-terminal",
      startedAt: Date.now(),
      phases: { process: { status: "running" } },
      activePhase: "process",
      activeMessage: "Investigating candidates",
      metrics: {},
      logs: Array.from({ length: 20 }, (_, index) => ({
        id: index + 1,
        level: "info" as const,
        message: `log ${index + 1}`,
      })),
      logOffset: 0,
      verbose: false,
    };

    const output = renderToString(
      createElement(Dashboard, {
        snapshot,
        onScroll: () => undefined,
        onFollow: () => undefined,
        onVerbose: () => undefined,
        terminalSize: { columns: 100, rows: 32 },
      }),
      { columns: 100 },
    );

    expect(output.split("\n")).toHaveLength(32);
    expect(output).toContain("log 8");
    expect(output).toContain("log 20");
    expect(output).not.toContain("log 7\n");
  });
});

import fs from "node:fs";
import path from "node:path";
import type { Severity } from "@deepsec/core";
import { BOLD, CYAN, DIM, GREEN, RESET, severityColor, YELLOW } from "../formatters.js";
import type { SetupWorkflowResult } from "./coordinator.js";
import { normalizeTerminalLine } from "./output.js";
import type { SetupOutputMode } from "./protocol.js";
import type { SetupPhase } from "./state.js";

export type SetupEvent =
  | { type: "phase-start"; phase: SetupPhase; label: string }
  | { type: "phase-skip"; phase: SetupPhase; reason: string }
  | { type: "phase-complete"; phase: SetupPhase; durationMs: number }
  | { type: "phase-error"; phase: SetupPhase; message: string }
  | {
      type: "log";
      phase?: SetupPhase;
      level: "debug" | "info" | "warn";
      message: string;
    }
  | {
      type: "progress";
      phase: SetupPhase;
      current?: number;
      total?: number;
      message?: string;
    }
  | {
      type: "metrics";
      phase: SetupPhase;
      values: Record<string, number | string>;
    };

export interface RecordedSetupEvent {
  sequence: number;
  timestamp: string;
  event: SetupEvent;
}

export interface SetupReporter {
  readonly interactive: boolean;
  readonly logPath?: string;
  emit(event: SetupEvent): void;
  suspend<T>(work: () => Promise<T>): Promise<T>;
  close(result: "success" | "error" | "cancelled"): Promise<void>;
}

export interface CreateSetupReporterOptions {
  workspaceDir: string;
  projectId: string;
  noTui?: boolean;
  env?: NodeJS.ProcessEnv;
  onCancel?: () => void;
  outputMode?: SetupOutputMode;
}

const TOKEN_PATTERNS = [
  /\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi,
  /\b(?:vck|vercel|sk|sess)-[A-Za-z0-9._-]{12,}\b/gi,
  /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
  /([a-z][a-z0-9+.-]*:\/\/[^\s/@:]+:)[^\s/@]+@/gi,
];

export function createSetupRedactor(
  env: NodeJS.ProcessEnv = process.env,
): (value: string) => string {
  const secrets = Object.entries(env)
    .filter(
      ([name, value]) =>
        Boolean(value) &&
        /(TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY|CREDENTIAL)/i.test(name) &&
        value!.length >= 8,
    )
    .map(([, value]) => value!)
    .sort((left, right) => right.length - left.length);
  return (input) => {
    let output = input;
    for (const secret of secrets) output = output.replaceAll(secret, "[REDACTED]");
    for (const pattern of TOKEN_PATTERNS) {
      output = output.replace(pattern, (_match, capture) =>
        typeof capture === "string" ? `${capture}[REDACTED]@` : "[REDACTED]",
      );
    }
    return output;
  };
}

export function sanitizeSetupEvent(
  event: SetupEvent,
  redact: (value: string) => string,
): SetupEvent {
  if (event.type === "log")
    return { ...event, message: redact(normalizeTerminalLine(event.message)) };
  if (event.type === "phase-error")
    return { ...event, message: redact(normalizeTerminalLine(event.message)) };
  if (event.type === "phase-skip")
    return { ...event, reason: redact(normalizeTerminalLine(event.reason)) };
  if (event.type === "progress" && event.message) {
    return { ...event, message: redact(normalizeTerminalLine(event.message)) };
  }
  return event;
}

export abstract class PersistentSetupReporter implements SetupReporter {
  abstract readonly interactive: boolean;
  readonly logPath: string;
  private sequence = 0;
  private readonly redact: (value: string) => string;

  constructor(options: CreateSetupReporterOptions) {
    const setupDir = path.join(options.workspaceDir, "data", options.projectId, "setup");
    fs.mkdirSync(setupDir, { recursive: true });
    const stamp = new Date()
      .toISOString()
      .replace(/[-:.TZ]/g, "")
      .slice(0, 14);
    this.logPath = path.join(setupDir, `setup-${stamp}-${process.pid}.jsonl`);
    fs.writeFileSync(this.logPath, "", { mode: 0o600 });
    this.redact = createSetupRedactor(options.env);
  }

  emit(event: SetupEvent): void {
    const safe = sanitizeSetupEvent(event, this.redact);
    const recorded: RecordedSetupEvent = {
      sequence: ++this.sequence,
      timestamp: new Date().toISOString(),
      event: safe,
    };
    fs.appendFileSync(this.logPath, `${JSON.stringify(recorded)}\n`);
    this.renderEvent(safe);
  }

  protected abstract renderEvent(event: SetupEvent): void;

  async suspend<T>(work: () => Promise<T>): Promise<T> {
    return await work();
  }

  async close(_result: "success" | "error" | "cancelled"): Promise<void> {}
}

class LineSetupReporter extends PersistentSetupReporter {
  readonly interactive = false;

  protected renderEvent(event: SetupEvent): void {
    switch (event.type) {
      case "phase-start":
        console.log(`→ ${event.label}`);
        break;
      case "phase-skip":
        console.log(`✓ ${event.reason}`);
        break;
      case "phase-complete":
        console.log(`✓ ${phaseLabel(event.phase)} (${formatDuration(event.durationMs)})`);
        break;
      case "phase-error":
        console.error(`✗ ${phaseLabel(event.phase)}: ${event.message}`);
        break;
      case "log":
        if (event.level === "warn") console.warn(event.message);
        break;
      case "progress":
      case "metrics":
        break;
    }
  }
}

class MachineSetupReporter extends PersistentSetupReporter {
  readonly interactive = false;
  private readonly outputMode: "json" | "jsonl";

  constructor(options: CreateSetupReporterOptions & { outputMode: "json" | "jsonl" }) {
    super(options);
    this.outputMode = options.outputMode;
  }

  protected renderEvent(event: SetupEvent): void {
    if (this.outputMode === "jsonl") {
      console.log(JSON.stringify({ type: "setup_event", event }));
    }
  }
}

export function phaseLabel(phase: SetupPhase): string {
  return (
    {
      scaffold: "Workspace",
      install: "Install",
      login: "Vercel and model access",
      info: "Threat model",
      "baseline-scan": "Baseline scan",
      coverage: "Coverage",
      matchers: "Generated matchers",
      "final-scan": "Final scan",
      process: "AI investigation",
    } satisfies Record<SetupPhase, string>
  )[phase];
}

export function formatDuration(durationMs: number): string {
  if (durationMs < 1_000) return `${durationMs}ms`;
  const seconds = Math.round(durationMs / 1_000);
  if (seconds < 60) return `${seconds}s`;
  return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

function visibleLength(value: string): number {
  return value.replace(/\x1b\[[0-9;]*m/g, "").length;
}

function summaryRow(columns: string[], widths: number[], rightAligned: number[] = []): string {
  return `│ ${columns
    .map((column, index) => {
      const padding = " ".repeat(Math.max(0, widths[index] - visibleLength(column)));
      return rightAligned.includes(index) ? `${padding}${column}` : `${column}${padding}`;
    })
    .join(" │ ")} │`;
}

function relativeDisplayPath(file: string, cwd: string): string {
  return (path.relative(cwd, file) || ".").split(path.sep).join("/");
}

function shellPath(file: string): string {
  if (/^[A-Za-z0-9_./-]+$/.test(file)) return file;
  return `'${file.replaceAll("'", `'\\''`)}'`;
}

function coloredSeverityCount(severity: Severity, count: number): string {
  if (count === 0) return `${DIM}0${RESET}`;
  return `${BOLD}${severityColor(severity)}${count}${RESET}`;
}

export function printSetupSummary(
  result: SetupWorkflowResult,
  options: {
    workspaceDir: string;
    projectId: string;
    logPath?: string;
    outputMode?: SetupOutputMode;
  },
): void {
  const cwd = process.cwd();
  const workspacePath = relativeDisplayPath(options.workspaceDir, cwd);
  const outputPath = "findings";
  const exportPathFromWorkspace = relativeDisplayPath(
    path.resolve(cwd, outputPath),
    options.workspaceDir,
  );
  if (!result.process || !result.processRunId || !result.coverage) {
    const partial = {
      type: "stopped",
      completed: false,
      stoppedAfter: result.stoppedAfter,
      projectId: options.projectId,
      workspace: workspacePath,
      model: result.state.agent,
      coverage: result.coverage,
      generatedMatchers: result.generatedMatchers,
      detailedLog: options.logPath
        ? relativeDisplayPath(options.logPath, process.cwd())
        : undefined,
      next: [...(workspacePath !== "." ? [`cd ${workspacePath}`] : []), "pnpm deepsec setup"],
    };
    if (options.outputMode && options.outputMode !== "human") {
      console.log(
        JSON.stringify(options.outputMode === "jsonl" ? partial : { ...partial, type: undefined }),
      );
    } else {
      console.log(
        `\n${GREEN}✓${RESET} Deepsec setup stopped after ${BOLD}${result.stoppedAfter}${RESET}`,
      );
      console.log(`${DIM}Resume from the next checkpoint with:${RESET}`);
      if (workspacePath !== ".") console.log(`  ${CYAN}cd ${shellPath(workspacePath)}${RESET}`);
      console.log(`  ${CYAN}pnpm deepsec setup${RESET}`);
    }
    return;
  }
  const coverage = result.coverage;
  const processResult = result.process;
  const coveredSurfaces = coverage.surfaces.filter((surface) => surface.passed).length;
  const coveredSurfaceFiles = coverage.surfaces.reduce(
    (total, surface) => total + surface.coveredFileCount,
    0,
  );
  const surfaceFiles = coverage.surfaces.reduce((total, surface) => total + surface.fileCount, 0);
  const coveredRepresentatives = coverage.surfaces.reduce(
    (total, surface) => total + surface.coveredRepresentativeFileCount,
    0,
  );
  const representatives = coverage.surfaces.reduce(
    (total, surface) => total + surface.representativeFileCount,
    0,
  );
  if (options.outputMode && options.outputMode !== "human") {
    const payload = {
      type: "complete",
      projectId: options.projectId,
      workspace: workspacePath,
      model: result.state.agent,
      coverage: {
        passed: coverage.passed,
        surfaces: { covered: coveredSurfaces, total: coverage.surfaces.length },
        surfaceFiles: { covered: coveredSurfaceFiles, total: surfaceFiles },
        representatives: { covered: coveredRepresentatives, total: representatives },
      },
      process: { ...processResult, runId: result.processRunId },
      generatedMatchers: result.generatedMatchers,
      files: {
        threatModel: relativeDisplayPath(
          path.join(options.workspaceDir, "data", options.projectId, "INFO.md"),
          cwd,
        ),
        matchers: relativeDisplayPath(
          path.join(options.workspaceDir, "generated-matchers.ts"),
          cwd,
        ),
        ...(options.logPath ? { detailedLog: relativeDisplayPath(options.logPath, cwd) } : {}),
      },
      next: [
        ...(workspacePath !== "." ? [`cd ${workspacePath}`] : []),
        "pnpm deepsec revalidate",
        `pnpm deepsec export --only-true-positive --format md-dir --out ${exportPathFromWorkspace}`,
      ],
    };
    console.log(
      JSON.stringify(options.outputMode === "jsonl" ? payload : { ...payload, type: undefined }),
    );
    return;
  }
  const findingLabel = processResult.findingCount === 1 ? "finding" : "findings";
  console.log(
    `\n${GREEN}✓${RESET} Deepsec found ${BOLD}${YELLOW}${processResult.findingCount} potential ${findingLabel}${RESET}`,
  );

  const widths = [13, 5, 5, 5, 5, 5, 5, 7];
  const border = (left: string, separator: string, right: string) =>
    `${left}${widths.map((width) => "─".repeat(width + 2)).join(separator)}${right}`;
  console.log(border("┌", "┬", "┐"));
  console.log(
    summaryRow(
      ["Investigated", "CRIT", "HIGH", "MED", "HBUG", "BUG", "LOW", "TOTAL"].map(
        (heading) => `${BOLD}${heading}${RESET}`,
      ),
      widths,
    ),
  );
  console.log(border("├", "┼", "┤"));
  console.log(
    summaryRow(
      [
        String(processResult.analysisCount),
        coloredSeverityCount("CRITICAL", processResult.findingsBySeverity.CRITICAL ?? 0),
        coloredSeverityCount("HIGH", processResult.findingsBySeverity.HIGH ?? 0),
        coloredSeverityCount("MEDIUM", processResult.findingsBySeverity.MEDIUM ?? 0),
        coloredSeverityCount("HIGH_BUG", processResult.findingsBySeverity.HIGH_BUG ?? 0),
        coloredSeverityCount("BUG", processResult.findingsBySeverity.BUG ?? 0),
        coloredSeverityCount("LOW", processResult.findingsBySeverity.LOW ?? 0),
        `${BOLD}${YELLOW}${processResult.findingCount}${RESET}`,
      ],
      widths,
      [0, 1, 2, 3, 4, 5, 6, 7],
    ),
  );
  console.log(border("└", "┴", "┘"));
  console.log(
    `${DIM}Coverage: ${coveredSurfaces}/${coverage.surfaces.length} surfaces · ${coveredSurfaceFiles}/${surfaceFiles} surface-file checks · ${coveredRepresentatives}/${representatives} representatives${RESET}`,
  );
  console.log(
    `${DIM}Analysis: ${result.state.agent.model}${result.state.agent.thinkingLevel ? ` · ${result.state.agent.thinkingLevel}` : ""} · $${processResult.costUsd.toFixed(4)} · run ${result.processRunId}${RESET}`,
  );

  console.log(`\n${BOLD}Next: revalidate the findings${RESET}`);
  console.log(`${DIM}Use AI to confirm true positives and remove false positives.${RESET}`);
  if (workspacePath !== ".") console.log(`  ${CYAN}cd ${shellPath(workspacePath)}${RESET}`);
  console.log(`  ${CYAN}pnpm deepsec revalidate${RESET}`);

  console.log(`\n${BOLD}Export the confirmed findings${RESET}`);
  console.log(
    `  ${CYAN}pnpm deepsec export --only-true-positive --format md-dir --out ${shellPath(exportPathFromWorkspace)}${RESET}`,
  );
  console.log(`  ${GREEN}→ ${BOLD}${outputPath}/${RESET}`);

  console.log(`\n${BOLD}Setup files${RESET}`);
  console.log(
    `  Threat model  ${relativeDisplayPath(path.join(options.workspaceDir, "data", options.projectId, "INFO.md"), cwd)}`,
  );
  if (result.generatedMatchers.accepted.length > 0) {
    console.log(
      `  Matchers      ${relativeDisplayPath(path.join(options.workspaceDir, "generated-matchers.ts"), cwd)} ${DIM}(${result.generatedMatchers.accepted.length} added)${RESET}`,
    );
  }
  if (options.logPath) {
    console.log(`  Detailed log  ${relativeDisplayPath(options.logPath, cwd)}`);
  }
}

export async function createSetupReporter(
  options: CreateSetupReporterOptions,
): Promise<SetupReporter> {
  if (options.outputMode === "json" || options.outputMode === "jsonl") {
    return new MachineSetupReporter({ ...options, outputMode: options.outputMode });
  }
  const interactive =
    !options.noTui &&
    process.stdin.isTTY === true &&
    process.stdout.isTTY === true &&
    process.env.TERM !== "dumb" &&
    !process.env.CI;
  if (!interactive) return new LineSetupReporter(options);
  try {
    const { InkSetupReporter } = await import("./tui.js");
    return new InkSetupReporter(options);
  } catch (error) {
    console.warn(
      `[deepsec] interactive dashboard unavailable; using line output: ${error instanceof Error ? error.message : String(error)}`,
    );
    return new LineSetupReporter(options);
  }
}

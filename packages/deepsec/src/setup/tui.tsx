import { Box, type Instance, render, Text, useInput, useWindowSize } from "ink";
// biome-ignore lint/correctness/noUnusedImports: root-level tsx uses the classic JSX runtime.
import React from "react";
import {
  formatDuration,
  PersistentSetupReporter,
  phaseLabel,
  type SetupEvent,
} from "./reporter.js";
import type { SetupPhase } from "./state.js";

const PHASES: SetupPhase[] = [
  "scaffold",
  "install",
  "login",
  "info",
  "baseline-scan",
  "coverage",
  "matchers",
  "final-scan",
  "process",
];

type PhaseStatus = "pending" | "running" | "complete" | "skipped" | "error";

export interface TuiSnapshot {
  projectId: string;
  startedAt: number;
  phases: Partial<Record<SetupPhase, { status: PhaseStatus; durationMs?: number }>>;
  activePhase?: SetupPhase;
  activeMessage?: string;
  metrics: Record<string, number | string>;
  logs: Array<{ id: number; level: "debug" | "info" | "warn"; message: string }>;
  logOffset: number;
  verbose: boolean;
  result?: "success" | "error" | "cancelled";
}

interface TerminalInput {
  setRawMode?: (mode: boolean) => unknown;
  ref(): unknown;
  resume(): unknown;
}

export function prepareTerminalInput(input: TerminalInput = process.stdin): void {
  input.setRawMode?.(false);
  input.ref();
  input.resume();
}

function statusGlyph(status: PhaseStatus | undefined): { glyph: string; color?: string } {
  if (status === "complete") return { glyph: "✓", color: "green" };
  if (status === "skipped") return { glyph: "↷", color: "gray" };
  if (status === "running") return { glyph: "●", color: "cyan" };
  if (status === "error") return { glyph: "✗", color: "red" };
  return { glyph: "○", color: "gray" };
}

export function Dashboard({
  snapshot,
  onCancel,
  onScroll,
  onFollow,
  onVerbose,
  terminalSize,
}: {
  snapshot: TuiSnapshot;
  onCancel?: () => void;
  onScroll: (delta: number) => void;
  onFollow: () => void;
  onVerbose: () => void;
  terminalSize?: { columns: number; rows: number };
}) {
  const windowSize = useWindowSize();
  const { columns, rows } = terminalSize ?? windowSize;
  useInput((input, key) => {
    if (key.ctrl && input === "c") onCancel?.();
    else if (key.upArrow) onScroll(1);
    else if (key.downArrow) onScroll(-1);
    else if (key.end) onFollow();
    else if (input === "v") onVerbose();
  });
  const elapsed = formatDuration(Date.now() - snapshot.startedAt);
  const eligibleLogs = snapshot.logs.filter((line) => snapshot.verbose || line.level !== "debug");
  const logEnd = Math.max(0, eligibleLogs.length - snapshot.logOffset);
  const metricEntries = Object.entries(snapshot.metrics).slice(-5);
  const phaseWidth = columns >= 100 ? 36 : 32;
  const rightWidth = Math.max(20, columns - phaseWidth - 1);
  const currentContentWidth = Math.max(1, rightWidth - 4);
  const messageRows = snapshot.activeMessage
    ? Math.max(1, Math.ceil(snapshot.activeMessage.length / currentContentWidth))
    : 0;
  const currentHeight = 4 + messageRows + metricEntries.length;
  // Header, body margin, footer, the Current panel, the Logs margin, and the
  // Logs title/border are fixed. Everything else becomes visible log rows.
  const logViewportRows = Math.max(1, rows - currentHeight - 7);
  const visibleLogs = eligibleLogs.slice(Math.max(0, logEnd - logViewportRows), logEnd);

  return (
    <Box flexDirection="column" width={columns} height={rows} overflow="hidden">
      <Box justifyContent="space-between">
        <Text bold color="cyan">
          deepsec setup · {snapshot.projectId}
        </Text>
        <Text dimColor>{elapsed}</Text>
      </Box>
      <Box marginTop={1} gap={1} flexGrow={1} overflow="hidden">
        <Box
          flexDirection="column"
          width={phaseWidth}
          paddingX={1}
          borderStyle="round"
          borderColor="gray"
        >
          <Text bold>Phases</Text>
          {PHASES.map((phase) => {
            const value = snapshot.phases[phase];
            const glyph = statusGlyph(value?.status);
            const duration =
              value?.durationMs !== undefined ? formatDuration(value.durationMs) : undefined;
            return (
              <Box key={phase} justifyContent="space-between">
                <Text color={glyph.color} wrap="truncate-end">
                  {glyph.glyph} {phaseLabel(phase)}
                </Text>
                {duration ? <Text dimColor>{duration}</Text> : null}
              </Box>
            );
          })}
        </Box>
        <Box flexDirection="column" flexGrow={1} overflow="hidden">
          <Box flexDirection="column" paddingX={1} borderStyle="round" borderColor="gray">
            <Text bold>Current</Text>
            <Text color="cyan">
              {snapshot.activePhase ? phaseLabel(snapshot.activePhase) : "Preparing"}
            </Text>
            {snapshot.activeMessage ? <Text>{snapshot.activeMessage}</Text> : null}
            {metricEntries.map(([name, value]) => (
              <Text key={name}>
                {name}: {value}
              </Text>
            ))}
          </Box>
          <Box
            marginTop={1}
            flexDirection="column"
            flexGrow={1}
            minHeight={3}
            paddingX={1}
            overflow="hidden"
            borderStyle="round"
            borderColor="gray"
          >
            <Text bold>Logs</Text>
            {visibleLogs.length === 0 ? <Text dimColor>Waiting for activity…</Text> : null}
            {visibleLogs.map((line) => (
              <Text
                key={line.id}
                wrap="truncate-end"
                color={line.level === "warn" ? "yellow" : undefined}
                dimColor={line.level === "debug"}
              >
                {line.message}
              </Text>
            ))}
          </Box>
        </Box>
      </Box>
      <Text dimColor>
        ↑/↓ logs · End follow · v {snapshot.verbose ? "normal" : "verbose"} · Ctrl-C cancel safely
      </Text>
    </Box>
  );
}

export class InkSetupReporter extends PersistentSetupReporter {
  readonly interactive = true;
  private readonly onCancel?: () => void;
  private instance?: Instance;
  private timer?: NodeJS.Timeout;
  private suspended = false;
  private nextLogId = 0;
  private snapshot: TuiSnapshot;

  constructor(options: {
    workspaceDir: string;
    projectId: string;
    env?: NodeJS.ProcessEnv;
    onCancel?: () => void;
  }) {
    super(options);
    this.onCancel = options.onCancel;
    this.snapshot = {
      projectId: options.projectId,
      startedAt: Date.now(),
      phases: {},
      metrics: {},
      logs: [],
      logOffset: 0,
      verbose: false,
    };
    this.enter();
  }

  protected renderEvent(event: SetupEvent): void {
    this.apply(event);
    this.scheduleRender();
  }

  private appendLog(level: "debug" | "info" | "warn", message: string): void {
    this.snapshot.logs.push({ id: ++this.nextLogId, level, message });
  }

  private apply(event: SetupEvent): void {
    if (event.type === "phase-start") {
      this.snapshot.phases[event.phase] = { status: "running" };
      this.snapshot.activePhase = event.phase;
      this.snapshot.activeMessage = event.label;
      this.snapshot.metrics = {};
      this.appendLog("info", `${event.label} started`);
    } else if (event.type === "phase-skip") {
      this.snapshot.phases[event.phase] = { status: "skipped" };
      this.snapshot.activeMessage = event.reason;
      this.appendLog("info", `${phaseLabel(event.phase)}: ${event.reason}`);
    } else if (event.type === "phase-complete") {
      this.snapshot.phases[event.phase] = {
        status: "complete",
        durationMs: event.durationMs,
      };
      this.appendLog(
        "info",
        `${phaseLabel(event.phase)} completed (${formatDuration(event.durationMs)})`,
      );
    } else if (event.type === "phase-error") {
      this.snapshot.phases[event.phase] = { status: "error" };
      this.snapshot.activeMessage = event.message;
      this.appendLog("warn", event.message);
    } else if (event.type === "log") {
      this.appendLog(event.level, event.message);
    } else if (event.type === "progress") {
      this.snapshot.activeMessage = event.message;
      if (event.current !== undefined) this.snapshot.metrics.current = event.current;
      if (event.total !== undefined) this.snapshot.metrics.total = event.total;
    } else if (event.type === "metrics") {
      this.snapshot.metrics = { ...this.snapshot.metrics, ...event.values };
    }
    if (this.snapshot.logs.length > 1_000) this.snapshot.logs.splice(0, 100);
  }

  private view() {
    return (
      <Dashboard
        snapshot={{ ...this.snapshot }}
        onCancel={this.onCancel}
        onScroll={(delta) => {
          this.snapshot.logOffset = Math.max(
            0,
            Math.min(this.snapshot.logs.length, this.snapshot.logOffset + delta),
          );
          this.instance?.rerender(this.view());
        }}
        onFollow={() => {
          this.snapshot.logOffset = 0;
          this.instance?.rerender(this.view());
        }}
        onVerbose={() => {
          this.snapshot.verbose = !this.snapshot.verbose;
          this.instance?.rerender(this.view());
        }}
      />
    );
  }

  private enter(): void {
    if (this.suspended || this.instance) return;
    process.stdout.write("\u001B[?1049h\u001B[?25l");
    this.instance = render(this.view(), { exitOnCtrlC: false, patchConsole: false });
  }

  private leave(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = undefined;
    this.instance?.unmount();
    this.instance = undefined;
    process.stdout.write("\u001B[?25h\u001B[?1049l");
  }

  private scheduleRender(): void {
    if (this.suspended || this.timer) return;
    this.timer = setTimeout(() => {
      this.timer = undefined;
      this.instance?.rerender(this.view());
    }, 100);
    this.timer.unref();
  }

  async suspend<T>(work: () => Promise<T>): Promise<T> {
    this.suspended = true;
    this.leave();
    // Ink unrefs stdin when it releases raw mode. readline can still print a
    // question on that stream, but its listeners do not ref the handle again;
    // with no other active handle Node exits while the prompt appears to wait.
    // Explicitly transfer terminal ownership to the suspended operation.
    prepareTerminalInput();
    try {
      return await work();
    } finally {
      this.suspended = false;
      this.enter();
    }
  }

  async close(result: "success" | "error" | "cancelled"): Promise<void> {
    this.snapshot.result = result;
    this.instance?.rerender(this.view());
    this.leave();
  }
}

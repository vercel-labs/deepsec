import fs from "node:fs";
import path from "node:path";
import type { SetupPhase, SetupState } from "./state.js";

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

export function buildSetupStatus(options: {
  workspaceDir: string;
  projectId: string;
  state?: SetupState;
}): Record<string, unknown> {
  const { state } = options;
  const outputIssue = (phase: SetupPhase): string | undefined => {
    if (
      phase === "install" &&
      !fs.existsSync(path.join(options.workspaceDir, "node_modules", "deepsec"))
    ) {
      return "node_modules/deepsec is missing";
    }
    if (
      phase === "info" &&
      (!fs.existsSync(path.join(options.workspaceDir, "data", options.projectId, "INFO.md")) ||
        !fs.existsSync(
          path.join(
            options.workspaceDir,
            "data",
            options.projectId,
            "setup",
            "surface-inventory.json",
          ),
        ))
    ) {
      return "threat model or surface inventory is missing";
    }
    if (phase === "process" && !state?.processRunId) return "process run id is missing";
    return undefined;
  };
  return {
    type: "status",
    projectId: options.projectId,
    workspace: options.workspaceDir,
    resumable: Boolean(state),
    currentPhase: state?.currentPhase,
    model: state?.agent,
    phases: PHASES.map((phase) => {
      const checkpoint = state?.phases[phase];
      const staleReason = checkpoint?.status === "complete" ? outputIssue(phase) : undefined;
      return {
        phase,
        status: staleReason ? "stale" : (checkpoint?.status ?? "pending"),
        reason:
          staleReason ??
          (checkpoint?.status === "complete"
            ? "checkpoint complete; inputs and outputs are revalidated on resume"
            : checkpoint?.status === "error"
              ? state?.lastError?.phase === phase
                ? state.lastError.message
                : "previous attempt failed"
              : "not completed yet"),
        startedAt: checkpoint?.startedAt,
        completedAt: checkpoint?.completedAt,
      };
    }),
    outputs: {
      threatModel: fs.existsSync(
        path.join(options.workspaceDir, "data", options.projectId, "INFO.md"),
      ),
      inventory: fs.existsSync(
        path.join(
          options.workspaceDir,
          "data",
          options.projectId,
          "setup",
          "surface-inventory.json",
        ),
      ),
      generatedMatchers: fs.existsSync(path.join(options.workspaceDir, "generated-matchers.ts")),
    },
    lastError: state?.lastError,
    updatedAt: state?.updatedAt,
  };
}

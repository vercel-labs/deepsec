import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { dataDir } from "@deepsec/core";
import type { DeclarativeMatcherSpec } from "@deepsec/scanner";
import { atomicWriteFileSync } from "../atomic-file.js";

export type SetupPhase =
  | "scaffold"
  | "install"
  | "login"
  | "info"
  | "baseline-scan"
  | "coverage"
  | "matchers"
  | "final-scan"
  | "process";

export interface PhaseCheckpoint {
  status: "running" | "complete" | "error";
  inputDigest: string;
  outputDigest?: string;
  operationKey?: string;
  startedAt: string;
  completedAt?: string;
}

export interface SetupState {
  version: 1;
  projectId: string;
  targetRoot: string;
  currentPhase?: SetupPhase;
  phases: Partial<Record<SetupPhase, PhaseCheckpoint>>;
  sourceFingerprint?: string;
  infoDigest?: string;
  inventoryDigest?: string;
  matcherDigest?: string;
  baselineScanRunId?: string;
  finalScanRunId?: string;
  baselineScanSummary?: {
    runId: string;
    languageStats: Array<{
      language: string;
      scannedFiles: number;
      candidates: number;
      matchRate: number;
    }>;
  };
  finalScanSummary?: {
    runId: string;
    languageStats: Array<{
      language: string;
      scannedFiles: number;
      candidates: number;
      matchRate: number;
    }>;
  };
  processRunId?: string;
  connection?: Record<string, unknown>;
  coverageReport?: unknown;
  matcherAttempts: Array<{
    proposedSlugs: string[];
    proposedSpecs?: DeclarativeMatcherSpec[];
    acceptedSlugs: string[];
    rejected: Array<{ slug: string; reason: string }>;
    outcome?: "empty-proposal" | "rescanned";
    scanRunId?: string;
  }>;
  setupLogPath?: string;
  agent: { type: string; model: string; thinkingLevel?: string };
  lastError?: { phase: string; code: string; message: string; at: string };
  updatedAt: string;
}

export function setupStatePath(projectId: string): string {
  return path.resolve(dataDir(projectId), "setup", "setup-state.json");
}

export function readSetupState(projectId: string): SetupState | undefined {
  const file = setupStatePath(projectId);
  if (!fs.existsSync(file)) return undefined;
  try {
    const parsed = JSON.parse(fs.readFileSync(file, "utf8")) as SetupState;
    if (parsed.version !== 1 || parsed.projectId !== projectId || !parsed.phases) return undefined;
    return parsed;
  } catch {
    return undefined;
  }
}

export function writeSetupState(state: SetupState): void {
  const file = setupStatePath(state.projectId);
  state.updatedAt = new Date().toISOString();
  atomicWriteFileSync(file, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
}

export function digest(value: unknown): string {
  return createHash("sha256")
    .update(typeof value === "string" ? value : JSON.stringify(value))
    .digest("hex");
}

export function isCheckpointCurrent(
  state: SetupState,
  phase: SetupPhase,
  inputDigest: string,
  outputExists: () => boolean = () => true,
): boolean {
  const checkpoint = state.phases[phase];
  return (
    checkpoint?.status === "complete" && checkpoint.inputDigest === inputDigest && outputExists()
  );
}

export function startPhase(
  state: SetupState,
  phase: SetupPhase,
  inputDigest: string,
  operationKey?: string,
): void {
  state.currentPhase = phase;
  state.lastError = undefined;
  state.phases[phase] = {
    status: "running",
    inputDigest,
    operationKey,
    startedAt: new Date().toISOString(),
  };
  writeSetupState(state);
}

export function completePhase(state: SetupState, phase: SetupPhase, outputDigest?: string): void {
  const checkpoint = state.phases[phase];
  if (!checkpoint) throw new Error(`Cannot complete setup phase ${phase}: it was not started`);
  checkpoint.status = "complete";
  checkpoint.outputDigest = outputDigest;
  checkpoint.completedAt = new Date().toISOString();
  state.currentPhase = undefined;
  writeSetupState(state);
}

export function failPhase(state: SetupState, phase: SetupPhase, error: unknown): void {
  const checkpoint = state.phases[phase];
  if (checkpoint) checkpoint.status = "error";
  state.lastError = {
    phase,
    code: error instanceof Error ? error.name : "Error",
    message: error instanceof Error ? error.message : String(error),
    at: new Date().toISOString(),
  };
  state.currentPhase = undefined;
  writeSetupState(state);
}

export function createSetupState(params: {
  projectId: string;
  targetRoot: string;
  agentType: string;
  model: string;
  thinkingLevel?: string;
}): SetupState {
  return {
    version: 1,
    projectId: params.projectId,
    targetRoot: path.resolve(params.targetRoot),
    phases: {},
    matcherAttempts: [],
    agent: {
      type: params.agentType,
      model: params.model,
      ...(params.thinkingLevel ? { thinkingLevel: params.thinkingLevel } : {}),
    },
    updatedAt: new Date().toISOString(),
  };
}

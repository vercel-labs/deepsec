import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { assertSafeFilePath, assertSafeSegment, dataDir } from "@deepsec/core";
import type { SandboxRunState } from "./types.js";

const RUNS_DIR = "sandbox-runs";

function runsDir(projectId: string): string {
  return path.join(dataDir(projectId), RUNS_DIR);
}

function runPath(projectId: string, runId: string): string {
  assertSafeSegment(runId, "sandbox runId");
  return path.join(runsDir(projectId), `${runId}.json`);
}

export function generateRunId(): string {
  const ts = new Date().toISOString().replace(/[-:T]/g, "").slice(0, 14);
  const suffix = crypto.randomBytes(8).toString("hex"); // 16 hex chars / 64 bits
  return `sbx-${ts}-${suffix}`;
}

export function saveRunState(state: SandboxRunState): void {
  validateRunState(state, state.projectId);
  const dir = runsDir(state.projectId);
  fs.mkdirSync(dir, { recursive: true });
  const dest = runPath(state.projectId, state.runId);
  // saveRunState is called once per run today (orchestrator.ts:335). With
  // a fresh 64-bit suffix collisions are vanishingly unlikely — but if it
  // happens we want a loud failure instead of silently destroying the
  // earlier run's manifest. Use O_EXCL so the kernel enforces it.
  const fd = fs.openSync(dest, "wx");
  try {
    fs.writeFileSync(fd, JSON.stringify(state, null, 2) + "\n");
  } finally {
    fs.closeSync(fd);
  }
}

export function loadRunState(projectId: string, runId: string): SandboxRunState {
  const p = runPath(projectId, runId);
  return validateRunState(JSON.parse(fs.readFileSync(p, "utf-8")), projectId);
}

export function deleteRunState(projectId: string, runId: string): void {
  try {
    fs.unlinkSync(runPath(projectId, runId));
  } catch {}
}

/** List all sandbox run states for a project, newest first */
export function listRunStates(projectId: string): SandboxRunState[] {
  const dir = runsDir(projectId);
  if (!fs.existsSync(dir)) return [];

  const states: SandboxRunState[] = [];
  for (const entry of fs.readdirSync(dir)) {
    if (!entry.endsWith(".json")) continue;
    try {
      states.push(
        validateRunState(JSON.parse(fs.readFileSync(path.join(dir, entry), "utf-8")), projectId),
      );
    } catch {}
  }
  return states.sort((a, b) => new Date(b.launchedAt).getTime() - new Date(a.launchedAt).getTime());
}

function validateRunState(value: unknown, expectedProjectId: string): SandboxRunState {
  if (!value || typeof value !== "object") throw new Error("Invalid sandbox run state");
  const s = value as SandboxRunState;
  assertSafeSegment(s.projectId, "projectId");
  if (s.projectId !== expectedProjectId) {
    throw new Error("Invalid sandbox run state: projectId mismatch");
  }
  assertSafeSegment(s.runId, "sandbox runId");
  if (!/^sbx-\d{14}-[a-f0-9]{16}$/.test(s.runId)) {
    throw new Error(`Invalid sandbox runId: ${JSON.stringify(s.runId)}`);
  }
  if (!Array.isArray(s.sandboxes)) throw new Error("Invalid sandbox run state: sandboxes");
  if (!["process", "revalidate", "triage", "scan", "report"].includes(s.command)) {
    throw new Error("Invalid sandbox run state: command");
  }
  const indexes = new Set<number>();
  for (const box of s.sandboxes) {
    if (!box || typeof box !== "object") throw new Error("Invalid sandbox entry");
    if (
      typeof box.sandboxId !== "string" ||
      box.sandboxId.length === 0 ||
      typeof box.cmdId !== "string" ||
      box.cmdId.length === 0
    ) {
      throw new Error("Invalid sandbox entry ids");
    }
    if (!Number.isInteger(box.index) || box.index < 0) {
      throw new Error("Invalid sandbox entry index");
    }
    if (indexes.has(box.index)) throw new Error("Invalid sandbox entry duplicate index");
    indexes.add(box.index);
    if (!Array.isArray(box.manifest) || !box.manifest.every((p) => typeof p === "string")) {
      throw new Error("Invalid sandbox entry manifest");
    }
    for (const p of box.manifest) assertSafeFilePath(p);
  }
  return s;
}

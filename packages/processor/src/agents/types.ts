import type { FileRecord, Finding, RefusalReport, RevalidationVerdict } from "@deepsec/core";

export interface AgentProgress {
  type: "started" | "tool_use" | "thinking" | "complete" | "error";
  message: string;
  candidateFile?: string;
}

export interface InvestigateParams {
  batch: FileRecord[];
  projectRoot: string;
  promptTemplate: string;
  projectInfo: string;
  config: Record<string, unknown>;
}

export interface InvestigateResult {
  filePath: string;
  findings: Finding[];
}

export interface BatchMeta {
  durationMs: number;
  durationApiMs?: number;
  numTurns?: number;
  costUsd?: number;
  agentSessionId?: string;
  usage?: {
    inputTokens: number;
    outputTokens: number;
    cacheReadInputTokens: number;
    cacheCreationInputTokens: number;
  };
  refusal?: RefusalReport;
  /**
   * Tail of the codex CLI's stderr log when an investigation produced 0
   * output tokens — captured by our wrapper so we can debug silent
   * failures (rate-limit, auth, etc.) that the SDK swallows on exit=0.
   * Empty/undefined for non-codex backends and successful codex runs.
   */
  codexStderr?: string;
  /**
   * True when the agent backend emitted one or more runtime errors while
   * handling the batch (quota/rate-limit/provider failures etc).
   */
  hadErrors?: boolean;
}

export interface InvestigateOutput {
  results: InvestigateResult[];
  meta: BatchMeta;
}

export interface RevalidateParams {
  batch: FileRecord[];
  projectRoot: string;
  projectInfo: string;
  config: Record<string, unknown>;
  /** When true, re-check findings that already have a revalidation verdict */
  force?: boolean;
}

export interface RevalidateVerdict {
  filePath: string;
  title: string;
  verdict: RevalidationVerdict;
  reasoning: string;
  adjustedSeverity?: "CRITICAL" | "HIGH" | "MEDIUM" | "HIGH_BUG" | "BUG";
}

export interface RevalidateOutput {
  verdicts: RevalidateVerdict[];
  meta: BatchMeta;
}

export interface AgentPlugin {
  type: string;
  investigate(params: InvestigateParams): AsyncGenerator<AgentProgress, InvestigateOutput>;
  revalidate(params: RevalidateParams): AsyncGenerator<AgentProgress, RevalidateOutput>;
}

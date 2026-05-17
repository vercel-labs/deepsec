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
  /**
   * Aborted by the processor when one batch trips a `QuotaExhaustedError`
   * — every other in-flight batch is hitting the same empty quota, so
   * letting them run wastes minutes. Plugins should pass this signal into
   * the underlying SDK (claude-agent-sdk: `abortController`; codex-sdk:
   * `runStreamed`'s `signal`) so the SDK terminates the in-flight HTTP
   * request rather than waiting for the next polled message.
   */
  signal?: AbortSignal;
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
  /** See InvestigateParams.signal — same semantics for revalidation. */
  signal?: AbortSignal;
}

export interface RevalidateVerdict {
  filePath: string;
  findingIndex?: number;
  title: string;
  verdict: RevalidationVerdict;
  reasoning: string;
  adjustedSeverity?: "CRITICAL" | "HIGH" | "MEDIUM" | "HIGH_BUG" | "BUG" | "LOW";
}

export interface RevalidateOutput {
  verdicts: RevalidateVerdict[];
  meta: BatchMeta;
}

export interface AgentPlugin {
  type: string;
  /** Deliberately replace an agent with the same type. Built-ins are reserved by default. */
  allowOverride?: boolean;
  investigate(params: InvestigateParams): AsyncGenerator<AgentProgress, InvestigateOutput>;
  revalidate(params: RevalidateParams): AsyncGenerator<AgentProgress, RevalidateOutput>;
}

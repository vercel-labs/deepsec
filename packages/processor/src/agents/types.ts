import type { FileRecord, Finding, RefusalReport, RevalidationVerdict } from "@deepsec/core";

export interface AgentProgress {
  type: "started" | "tool_use" | "thinking" | "complete" | "error";
  message: string;
  candidateFile?: string;
}

/** A general read-only repository task used by first-run setup. */
export interface SetupTaskParams {
  prompt: string;
  projectRoot: string;
  config: Record<string, unknown>;
  signal?: AbortSignal;
  onProgress?: (progress: AgentProgress) => void;
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
  /**
   * Project id, used by agent plugins for debug-log placement (e.g.
   * raw agent output that failed JSON parsing is written under
   * `data/<projectId>/debug/` so it survives a sandbox run via the
   * normal tarball download).
   */
  projectId?: string;
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
  /**
   * Restrict the prompt to exactly these findingIds. Used by the
   * processor's adaptive-split retries: after a partial batch is
   * persisted, only the unresolved findings are re-requested —
   * regardless of `force` and of what got a verdict in the meantime.
   */
  onlyFindingIds?: string[];
  /** See InvestigateParams.signal — same semantics for revalidation. */
  signal?: AbortSignal;
  /** See InvestigateParams.projectId — used for debug-log placement. */
  projectId?: string;
}

export interface RevalidateVerdict {
  /**
   * Primary identity in the response contract: the stable `findingId`
   * echoed back from the prompt. Old responses (and old prompts) carry
   * filePath+title instead — the reconciliation layer accepts either.
   */
  findingId?: string;
  filePath?: string;
  title?: string;
  verdict: RevalidationVerdict;
  reasoning: string;
  adjustedSeverity?: "CRITICAL" | "HIGH" | "MEDIUM" | "HIGH_BUG" | "BUG";
  /**
   * Required when `verdict === "duplicate"`. The `findingId` of the
   * primary finding (preferred), or its `title` for legacy responses —
   * the canonical finding that should keep its real verdict. The
   * processor rejects DUPEs that don't reference a non-DUPE primary.
   */
  duplicateOf?: string;
}

/**
 * One raw agent response captured during a revalidation batch — the
 * initial answer plus any repair turns. Persisted verbatim under the
 * project data dir so mismatches can be diagnosed and rescored without
 * repeating model work.
 */
export interface RevalidateRawResponse {
  kind: "initial" | "json-repair" | "id-repair";
  /** The follow-up prompt that produced this response (repair turns only). */
  prompt?: string;
  rawText: string;
  /** How many verdicts parsed out of this response (undefined if parsing failed). */
  parsedCount?: number;
}

export interface RevalidateOutput {
  verdicts: RevalidateVerdict[];
  meta: BatchMeta;
  /**
   * Raw model responses (initial + repair turns) for artifact logging.
   * Optional: plugins that predate the field simply produce no artifact.
   */
  rawResponses?: RevalidateRawResponse[];
  /** Number of in-session id-repair turns the plugin ran. */
  repairAttempts?: number;
}

export interface AgentPlugin {
  type: string;
  investigate(params: InvestigateParams): AsyncGenerator<AgentProgress, InvestigateOutput>;
  revalidate(params: RevalidateParams): AsyncGenerator<AgentProgress, RevalidateOutput>;
}

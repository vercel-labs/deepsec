// --- Run tracking ---

export interface RunMeta {
  runId: string;
  projectId: string;
  rootPath: string;
  createdAt: string;
  completedAt?: string;
  type: "scan" | "process" | "revalidate";
  phase: "running" | "done" | "error";
  /**
   * OS process id of the run owner, captured at `createRunMeta`. Combined
   * with `hostname` it lets `isReclaimableLock` detect crashed runs
   * (SIGKILL / OOM / power loss) on the same host immediately, instead of
   * waiting out the 1h `STALE_LOCK_MS` for `phase === "running"` runs that
   * will never call `completeRun`. Optional for backward compat with run
   * metas written before this field existed.
   */
  pid?: number;
  /**
   * Hostname of the machine the run was started on. PID liveness is only
   * meaningful on the same host; cross-host stale runs still fall back to
   * the timestamp-based staleness check.
   */
  hostname?: string;
  scannerConfig?: {
    matcherSlugs: string[];
    /**
     * Scan mode. "full" (default, omitted on legacy runs) is the
     * whole-repo glob-driven scan. "files" means the run was bounded to
     * an explicit file list (e.g. `process --diff`); FileRecords were
     * written for every listed file even when no matchers fired.
     */
    mode?: "full" | "files";
    /**
     * Where the file list came from. Free-form label like
     * "git-diff:origin/main" or "files:cli". Only meaningful when
     * mode === "files".
     */
    source?: string;
    /** Number of files in the explicit list. Only set when mode === "files". */
    fileCount?: number;
  };
  processorConfig?: {
    agentType: string;
    model: string;
    modelConfig: Record<string, unknown>;
    /**
     * "scan" (default, omitted on legacy runs) means process pulled work
     * from the scanner's pending file queue. "direct" means the file
     * list was passed in explicitly (e.g. `process --diff`) and the
     * scanner-state filtering was bypassed.
     */
    invocationMode?: "scan" | "direct";
    /**
     * Origin label for direct invocations: "git-diff:origin/main",
     * "files:cli", "files-from:-", etc. Only meaningful when
     * invocationMode === "direct".
     */
    source?: string;
  };
  stats: {
    filesScanned?: number;
    candidatesFound?: number;
    filesProcessed?: number;
    findingsCount?: number;
    totalCostUsd?: number;
    totalInputTokens?: number;
    totalOutputTokens?: number;
    totalDurationMs?: number;
    findingsRevalidated?: number;
    truePositives?: number;
    falsePositives?: number;
    fixed?: number;
    uncertain?: number;
    duplicates?: number;
  };
}

// --- Scanner match (part of FileRecord) ---

export interface CandidateMatch {
  vulnSlug: string;
  lineNumbers: number[];
  snippet: string;
  matchedPattern: string;
}

// --- Analysis entry (append-only history in FileRecord) ---

export interface RefusalReport {
  refused: boolean;
  reason?: string;
  skipped?: Array<{ filePath?: string; reason: string }>;
  /** Raw model response to the follow-up question (trimmed), for debugging */
  raw?: string;
}

export interface AnalysisEntry {
  runId: string;
  investigatedAt: string;
  durationMs: number;
  durationApiMs?: number;
  agentType: string;
  model: string;
  modelConfig: Record<string, unknown>;
  agentSessionId?: string;
  findingCount: number;
  numTurns?: number;
  /**
   * Which run-type produced this entry. `process` = an investigation run
   * appended findings to the file; `revalidate` = a revalidation run
   * applied verdicts to existing findings (no new findings expected).
   *
   * Optional for backward compat: entries written before this field
   * existed are implicitly `process`. Aggregators that want to bucket
   * the two should treat missing as `process`.
   *
   * The `--reinvestigate <N>` filter in `process()` and the sandbox
   * partitioner explicitly ignore entries where `phase === "revalidate"`
   * — a revalidate pass shouldn't count as "this file has already been
   * processed by this agent for wave N".
   */
  phase?: "process" | "revalidate";
  /**
   * Per-file share of batch-level cost. The agent reports cost / tokens
   * for the whole batch (one API call covers N files); we divide evenly
   * so summing per-file entries gives the correct run total. Pre-fix
   * entries hold the *batch* total stamped on every file, which inflates
   * `metrics` cost roughly by batch size.
   */
  costUsd?: number;
  /**
   * Per-file share of batch-level token usage. Same divide-by-N split
   * as `costUsd`.
   */
  usage?: {
    inputTokens: number;
    outputTokens: number;
    cacheReadInputTokens: number;
    cacheCreationInputTokens: number;
  };
  refusal?: RefusalReport;
  /**
   * Tail of codex CLI stderr captured by our wrapper when an investigation
   * produced 0 output tokens (gateway soft-fail / silent failure). Used
   * for forensic debugging; truncated to ~3000 chars.
   */
  codexStderr?: string;
  /**
   * The `--reinvestigate <N>` value the run was started with — recorded as
   * a wave/generation marker. Re-running with the same N skips files that
   * already have a productive analysis bearing this marker for the same
   * agent. Absent on first-time analyses (status=pending) and on runs
   * started with bare `--reinvestigate` (no number).
   */
  reinvestigateMarker?: number;
}

// --- Finding (produced by processor agent) ---

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "HIGH_BUG" | "BUG" | "LOW";
export type Confidence = "high" | "medium" | "low";

export type RevalidationVerdict =
  | "true-positive"
  | "false-positive"
  | "fixed"
  | "uncertain"
  // Manual marker (the agent never sets this): real true-positive that
  // the team has consciously chosen to accept. See the schema comment in
  // `schemas.ts` and the "Accepted risks" section of the project README.
  | "accepted-risk"
  // The agent flagged this finding as a duplicate of another finding in
  // the same file. The canonical one keeps its real verdict; duplicates
  // point at it via `duplicateOf` (the primary's `title`). The processor
  // enforces that the primary itself is not a duplicate so each
  // equivalence class has exactly one non-duplicate.
  | "duplicate";

export interface Revalidation {
  verdict: RevalidationVerdict;
  reasoning: string;
  adjustedSeverity?: Severity;
  /**
   * Set iff `verdict === "duplicate"`. Holds the identity of the primary
   * finding — the `findingId` when known (new writes), or the primary's
   * `title` for records written before finding IDs existed. The
   * primary's verdict is the canonical one for the underlying issue.
   */
  duplicateOf?: string;
  revalidatedAt: string;
  runId: string;
  model: string;
}

export type TriagePriority = "P0" | "P1" | "P2" | "skip";

export interface Triage {
  priority: TriagePriority;
  exploitability: "trivial" | "moderate" | "difficult";
  impact: "critical" | "high" | "medium" | "low";
  reasoning: string;
  triagedAt: string;
  model: string;
}

export interface Finding {
  /**
   * Stable, deterministic identifier: `finding_` + sha256 prefix of
   * (projectId, normalized filePath, original title). Assigned at append
   * time for new findings and lazily backfilled on load for records
   * written before the field existed (see `ensureFindingIds`). This is
   * the primary identity used by the revalidation response contract —
   * titles are human-readable context only.
   *
   * Optional in the schema for backward compatibility, but always
   * present in memory after a record passes through
   * readFileRecord/loadAllFileRecords.
   */
  findingId?: string;
  severity: Severity;
  vulnSlug: string;
  title: string;
  description: string;
  lineNumbers: number[];
  recommendation: string;
  confidence: Confidence;
  triage?: Triage;
  revalidation?: Revalidation;
  /**
   * The run that first surfaced this finding (the one that appended it
   * to `FileRecord.findings`). Set once at append time and never updated
   * — re-runs that re-report the same signature get deduped, so this
   * stays bound to the original discovery.
   *
   * Optional for backward compatibility with findings written before
   * this field existed.
   */
  producedByRunId?: string;
}

// --- Ownership oracle types ---

export interface OwnershipContributor {
  email: string;
  name: string;
  github_username: string;
  score: number;
  context: string;
  last_contrib: string;
}

export interface OwnershipEscalationTeam {
  name: string;
  slug: string;
  source: string;
  escalation_path_id: string;
  slack_channel_id: string | null;
  manager: {
    email: string;
    slack_user_id: string;
  };
  current_oncall: {
    name: string;
    email: string;
    slack_user_id: string;
    github_username: string;
  };
}

export interface OwnershipApprover {
  owner: string;
  owner_type: string;
  pattern: string | null;
  is_primary: boolean;
  is_direct: boolean;
}

export interface OwnershipData {
  contributors: OwnershipContributor[];
  escalationTeams: OwnershipEscalationTeam[];
  approvers: OwnershipApprover[];
  fetchedAt: string;
}

// --- FileRecord: the core per-file accumulator ---

export type FileStatus = "pending" | "processing" | "analyzed" | "error";

export interface FileRecord {
  filePath: string;
  projectId: string;

  // Scanner results — merged across scans
  candidates: CandidateMatch[];
  lastScannedAt: string;
  lastScannedRunId: string;
  fileHash: string;

  // Analysis results — latest findings + history
  findings: Finding[];
  analysisHistory: AnalysisEntry[];

  // Git enrichment
  gitInfo?: {
    recentCommitters: { name: string; email: string; date: string }[];
    enrichedAt: string;
    // Ownership oracle data (primary source when available)
    ownership?: OwnershipData;
  };

  // Status & locking
  status: FileStatus;
  lockedByRunId?: string;
  /**
   * ISO timestamp when `status` last transitioned to `processing` and
   * `lockedByRunId` was set. Used by the work selector to decide when
   * a `processing` record from another run is reclaimable: only when
   * the lock is older than `STALE_LOCK_MS` AND the locking run's
   * RunMeta is `done` / `error` / missing. Without this, two
   * overlapping `process()` runs could both pick up the same record
   * and clobber each other's findings on write.
   *
   * Optional for backward compatibility with records written before
   * this field existed. Missing values are treated as "very old" so
   * legacy locked records can still be reclaimed when their owning
   * run is no longer alive.
   */
  lockedAt?: string;
}

// --- Project config ---

export interface ProjectConfig {
  projectId: string;
  rootPath: string;
  createdAt: string;
  githubUrl?: string;
}

// --- Run tracking ---

export interface RunMeta {
  runId: string;
  projectId: string;
  rootPath: string;
  createdAt: string;
  completedAt?: string;
  type: "scan" | "process" | "revalidate";
  phase: "running" | "done" | "error";
  scannerConfig?: {
    matcherSlugs: string[];
  };
  processorConfig?: {
    agentType: string;
    model: string;
    modelConfig: Record<string, unknown>;
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
  costUsd?: number;
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

/** Severity rank, lower is more severe. Used by `--min-severity` filter and severity sort. */
export const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  HIGH_BUG: 3,
  BUG: 4,
  LOW: 5,
};

export type RevalidationVerdict = "true-positive" | "false-positive" | "fixed" | "uncertain";

export interface Revalidation {
  verdict: RevalidationVerdict;
  reasoning: string;
  adjustedSeverity?: Severity;
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
  severity: Severity;
  vulnSlug: string;
  title: string;
  description: string;
  lineNumbers: number[];
  recommendation: string;
  confidence: Confidence;
  triage?: Triage;
  revalidation?: Revalidation;
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
}

// --- Project config ---

export interface ProjectConfig {
  projectId: string;
  rootPath: string;
  createdAt: string;
  githubUrl?: string;
}

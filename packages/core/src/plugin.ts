import type { CandidateMatch, FileRecord, Finding, OwnershipData } from "./types.js";

// --- Scanner ---

/** How noisy (false-positive-prone) a matcher is. Used to rank processing order. */
export type NoiseTier = "precise" | "normal" | "noisy";

/**
 * Optional gate that controls whether a matcher runs at all on a given repo.
 * Resolved once per scan against the project root, not once per file. Matchers
 * without a gate run unconditionally (backwards compatible).
 *
 * The gate has two layers:
 *
 * 1. `tech` (preferred shorthand) — matches against the normalized tag list
 *    produced by `detectTech()`. Cheap and dependency-free; just say "this
 *    matcher needs Laravel" and the registry handles the rest.
 *
 * 2. `sentinelFiles` + optional `sentinelContains` — for cases where
 *    detectTech doesn't yet know about your stack, or you want a finer
 *    check than a tag (e.g. only Laravel projects with Livewire installed).
 *    Globs are evaluated once per scan against the project root.
 */
export interface MatcherGate {
  /**
   * Any-of: matcher runs if at least one of these tags is present in the
   * detected tech list. Tags are lowercase short names (`"laravel"`,
   * `"nextjs"`, `"django"`, `"rails"`).
   */
  tech?: string[];
  /** Any-of: at least one of these paths must exist (globs allowed). */
  sentinelFiles?: string[];
  /**
   * When a sentinel path matches, the file content must also satisfy this
   * predicate. Used when a generic sentinel (`composer.json`,
   * `package.json`) needs deeper inspection ("does composer.json depend
   * on `laravel/framework`?"). Receives the relative path that matched
   * and the file content.
   */
  sentinelContains?: (path: string, content: string) => boolean;
}

export interface MatcherPlugin {
  slug: string;
  description: string;
  noiseTier: NoiseTier;
  filePatterns: string[];
  /**
   * Optional. When present, the matcher only runs if the gate evaluates
   * truthy against the project root. Omitted means "always run" — preserves
   * the behavior of every matcher written before this field existed.
   */
  requires?: MatcherGate;
  /**
   * Optional inline test cases. Each string is a snippet that this
   * matcher MUST flag (i.e. produce ≥ 1 candidate for). A single
   * discovery test (`packages/scanner/src/__tests__/matcher-examples.test.ts`)
   * iterates every matcher in the registry and asserts each example
   * fires.
   *
   * The point is to keep matcher tests next to the regex they test,
   * with as little boilerplate as possible — adding a new case is one
   * line, and the strings double as human-readable documentation of
   * what the matcher is meant to catch. Good practice: cover EVERY
   * sub-pattern in the matcher's regex list, plus realistic syntactic
   * variants (different verbs, casing, identifiers, whitespace) so a
   * typo on any sub-pattern fails CI.
   *
   * Examples are not used at runtime and don't affect scanning. They
   * are a development-time contract.
   */
  examples?: string[];
  match(content: string, filePath: string): CandidateMatch[];
}

// --- People / ownership ---

/**
 * Generic person record returned by a `PeopleProvider`. Plugin-specific fields
 * (Slack ID, GitHub handle, etc.) live under `extra`.
 */
export interface Person {
  name: string;
  email: string;
  title?: string | null;
  department?: string | null;
  profileUrl?: string | null;
  /** Identifier the provider would use to look up this person's manager. */
  managerKey?: string | null;
  extra?: Record<string, unknown>;
}

export interface OwnershipProvider {
  name: string;
  /**
   * Look up ownership data for a file in a repository. Returning `null` is
   * a "not configured / not available" signal — callers should treat it as
   * a soft failure, not an error.
   */
  fetchOwnership(args: { filePath: string; repo: string }): Promise<OwnershipData | null>;
}

export interface PeopleProvider {
  name: string;
  lookup(query: string): Promise<Person | null>;
  lookupManager?(person: Person): Promise<Person | null>;
}

// --- Notifiers ---

export interface NotifyParams {
  finding: Finding;
  record: FileRecord;
  projectId: string;
}

/** Generic record describing where a finding has been reported. */
export interface FindingNotification {
  notifierName: string;
  notifiedAt: string;
  /** Notifier-defined identifier — Slack message ts, GitHub issue id, etc. */
  externalId?: string;
  externalUrl?: string;
  extra?: Record<string, unknown>;
}

export interface NotifierPlugin {
  name: string;
  notify(params: NotifyParams): Promise<FindingNotification>;
}

// --- Remote executor ---

/**
 * A request to run a deepsec subcommand somewhere other than the local
 * machine. The shape is intentionally loose — backend-specific options live
 * under `options`.
 */
export interface ExecutorLaunchRequest {
  projectId: string;
  /** Subcommand to run (e.g. "process", "revalidate"). */
  command: string;
  /** Files the work should be partitioned over. */
  files: string[];
  /** Total parallelism to target across the executor. */
  parallelism?: number;
  timeoutMs?: number;
  env?: Record<string, string>;
  options?: Record<string, unknown>;
}

export interface ExecutorStatus {
  runId: string;
  state: "running" | "done" | "error";
  message?: string;
}

export interface ExecutorProvider {
  name: string;
  /** Launch a run; returns a runId callers can use with `collect` / `status`. */
  launch(req: ExecutorLaunchRequest, onLog: (msg: string) => void): Promise<string>;
  /** Pull results from a completed run into the local data directory. */
  collect(runId: string): Promise<void>;
  status?(runId: string): Promise<ExecutorStatus>;
}

// --- Agent backends ---
// AgentPlugin is defined in @deepsec/processor and re-shipped via plugins by
// reference — the field below intentionally accepts any shape so core stays
// dependency-free. The processor validates the actual contract at use site.

export type AgentPluginRef = unknown;

// --- Umbrella plugin ---

export interface DeepsecPlugin {
  name: string;
  matchers?: MatcherPlugin[];
  agents?: AgentPluginRef[];
  notifiers?: NotifierPlugin[];
  /** Last plugin to declare this wins. */
  ownership?: OwnershipProvider;
  /** Last plugin to declare this wins. */
  people?: PeopleProvider;
  /** Last plugin to declare this wins. */
  executor?: ExecutorProvider;
  /**
   * Hook for plugins to register their own CLI subcommands. Receives a
   * Commander program (typed loosely to avoid a commander dep in core).
   */
  commands?: (program: unknown) => void;
}

import type { Sandbox } from "@vercel/sandbox";

/** Supported subcommands for sandbox execution. `enrich` is intentionally
 * absent — enrichment runs locally (git committer lookups + plugin ownership
 * calls) and isn't AI-bound, so the fan-out cost outweighs the benefit. */
export type SandboxSubcommand = "process" | "revalidate" | "triage" | "scan" | "report";

export interface SandboxConfig {
  projectId: string;
  /** Which deepsec subcommand to run */
  command: SandboxSubcommand;
  /** Number of parallel sandboxes */
  sandboxCount: number;
  /** vCPUs per sandbox (default: 2, max: 8) */
  vcpus: number;
  /** Total files to process across all sandboxes */
  limit?: number;
  /** Concurrency within each sandbox (passed to --concurrency) */
  concurrency: number;
  /** Batch size within each sandbox */
  batchSize: number;
  /** Agent backend type — claude-agent-sdk or codex */
  agentType?: string;
  /** Model to use */
  model: string;
  /** Restore from existing snapshot */
  snapshotId?: string;
  /** Snapshot after setup for reuse */
  saveSnapshot: boolean;
  /** Don't stop sandboxes after completion */
  keepAlive: boolean;
  /** Re-investigate already-analyzed files. `true` = all, number = files with < N analyses */
  reinvestigate: boolean | number;
  /** Force re-check (for revalidate, triage) */
  force: boolean;
  /** Min severity filter (for revalidate, triage) */
  minSeverity?: string;
  /** Path prefix filter */
  filter?: string;
  /** Comma-separated matcher slugs (for scan) */
  matchers?: string;
  /** Sandbox timeout in ms (default: 5 hours for Pro) */
  timeout: number;
  /** Extra hostnames to allow through worker egress firewall (in addition to the AI host derived from base URLs) */
  allowedHosts?: string[];
  /** Extra CLI args to pass through to the subcommand */
  extraArgs: string[];
}

export interface SandboxInstance {
  sandbox: Sandbox;
  index: number;
  sandboxId: string;
  status: "creating" | "setup" | "running" | "collecting" | "done" | "error";
  manifest: string[];
  error?: string;
}

export interface PartitionResult {
  partitions: string[][];
  totalFiles: number;
}

export interface SandboxResult {
  sandboxIndex: number;
  sandboxId: string;
  success: boolean;
  filesProcessed: number;
  error?: string;
  cpuUsageMs?: number;
  networkUsage?: { ingress: number; egress: number };
}

/** Persisted state for a detached sandbox run */
export interface SandboxRunState {
  runId: string;
  projectId: string;
  command: SandboxSubcommand;
  vcpus: number;
  launchedAt: string;
  sandboxes: {
    sandboxId: string;
    cmdId: string;
    index: number;
    manifest: string[];
  }[];
}

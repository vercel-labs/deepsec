import { defaultModelForAgent } from "../agent-defaults.js";
import { BOLD, CYAN, DIM, GREEN, RED, RESET } from "../formatters.js";
import { assertAgentCredential, assertSandboxCredential } from "../preflight.js";
import { resolveAgentType } from "../resolve-agent-type.js";
import { resolveProjectId } from "../resolve-project-id.js";
import {
  boundedInt,
  parseBoundedFlag,
  parseBoundedOptionalFlag,
  SANDBOX_LIMITS,
} from "../sandbox/limits.js";
import { checkStatus, collect, launch, orchestrate } from "../sandbox/orchestrator.js";
import type { SandboxConfig, SandboxSubcommand } from "../sandbox/types.js";

const VALID_COMMANDS: SandboxSubcommand[] = ["process", "revalidate", "triage", "scan", "report"];

interface SandboxOpts {
  projectId?: string;
  sandboxes?: number;
  vcpus?: number;
  snapshotId?: string;
  trustSnapshotId?: boolean;
  saveSnapshot?: boolean;
  keepAlive?: boolean;
  detach?: boolean;
  runId?: string;
  timeout?: number;
  args?: string[];
}

/**
 * Extract a value for a named flag from the passthrough args array.
 * e.g. extractFlag(["--limit", "50", "--force"], "--limit") => "50"
 */
function extractFlag(args: string[], flag: string): string | undefined {
  const idx = args.indexOf(flag);
  if (idx === -1 || idx + 1 >= args.length) return undefined;
  const val = args[idx + 1];
  if (val.startsWith("--")) return undefined;
  return val;
}

function hasFlag(args: string[], flag: string): boolean {
  return args.includes(flag);
}

/**
 * Extract `--reinvestigate` in its optional-arg form. Returns:
 *   undefined — flag not present
 *   true      — flag present with no value (bare)
 *   number    — flag present with a positive integer value (--reinvestigate 2)
 */
export function extractReinvestigate(args: string[]): boolean | number | undefined {
  const idx = args.indexOf("--reinvestigate");
  if (idx === -1) return undefined;
  const val = args[idx + 1];
  if (val && !val.startsWith("--")) {
    const n = parseInt(val, 10);
    if (!Number.isNaN(n) && n >= 1) return n;
  }
  return true;
}

function buildConfig(
  subcommand: SandboxSubcommand,
  projectId: string,
  opts: SandboxOpts,
): SandboxConfig {
  const args = opts.args ?? [];
  const concurrency = parseBoundedFlag(extractFlag(args, "--concurrency"), "--concurrency", {
    defaultValue: 4,
    min: 1,
    max: SANDBOX_LIMITS.maxConcurrency,
  });
  // Auto-derive vCPUs from concurrency if not explicitly set (max 8, must be even)
  const derivedVcpus = Math.min(Math.ceil(concurrency / 2) * 2, SANDBOX_LIMITS.maxVcpus);
  const vcpus = boundedInt(opts.vcpus, "--vcpus", {
    defaultValue: derivedVcpus,
    min: 1,
    max: SANDBOX_LIMITS.maxVcpus,
  });
  const agentType = resolveAgentType(extractFlag(args, "--agent"));
  return {
    projectId,
    command: subcommand,
    sandboxCount: boundedInt(opts.sandboxes, "--sandboxes", {
      defaultValue: 1,
      min: 1,
      max: SANDBOX_LIMITS.maxSandboxes,
    }),
    vcpus,
    // Extract key values from passthrough args for orchestrator/partitioner use
    limit: parseBoundedOptionalFlag(extractFlag(args, "--limit"), "--limit", {
      min: 1,
      max: SANDBOX_LIMITS.maxLimit,
    }),
    concurrency,
    batchSize: parseBoundedFlag(extractFlag(args, "--batch-size"), "--batch-size", {
      defaultValue: 5,
      min: 1,
      max: SANDBOX_LIMITS.maxBatchSize,
    }),
    agentType,
    model: extractFlag(args, "--model") ?? defaultModelForAgent(agentType),
    snapshotId: opts.snapshotId,
    saveSnapshot: opts.saveSnapshot ?? false,
    keepAlive: opts.keepAlive ?? false,
    reinvestigate: extractReinvestigate(args) ?? false,
    force: hasFlag(args, "--force"),
    minSeverity: extractFlag(args, "--min-severity") ?? extractFlag(args, "--severity"),
    filter: extractFlag(args, "--filter"),
    matchers: extractFlag(args, "--matchers"),
    timeout: boundedInt(opts.timeout, "--timeout", {
      defaultValue: 5 * 60 * 60 * 1000,
      min: SANDBOX_LIMITS.minTimeoutMs,
      max: SANDBOX_LIMITS.maxTimeoutMs,
    }),
    extraArgs: args,
  };
}

function makeLogger(startTime: number) {
  return (msg: string) => {
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(0);
    console.log(`${DIM}[${elapsed}s]${RESET} ${msg}`);
  };
}

function printResults(
  results: { success: boolean; sandboxIndex: number; filesProcessed: number; error?: string }[],
  startTime: number,
) {
  console.log();
  console.log(`${BOLD}Results:${RESET}`);
  let totalProcessed = 0;
  let totalErrors = 0;
  for (const r of results) {
    if (r.success) {
      const detail = r.filesProcessed > 0 ? `${r.filesProcessed} files` : "done";
      console.log(`  ${GREEN}sandbox-${r.sandboxIndex}${RESET}: ${detail}`);
      totalProcessed += r.filesProcessed;
    } else {
      console.log(`  ${RED}sandbox-${r.sandboxIndex}${RESET}: FAILED — ${r.error}`);
      totalErrors++;
    }
  }
  console.log();
  if (totalProcessed > 0) {
    console.log(`${BOLD}Total:${RESET} ${totalProcessed} files, ${totalErrors} sandbox(es) failed`);
  } else {
    console.log(
      `${BOLD}Total:${RESET} ${results.length - totalErrors} succeeded, ${totalErrors} failed`,
    );
  }
  console.log(
    `${DIM}Duration: ${((Date.now() - startTime) / 1000 / 60).toFixed(1)} minutes${RESET}`,
  );
}

/**
 * `sandbox <deepsec-command>` — run attached (default) or detached (--detach)
 */
export async function sandboxCommand(subcommand: string, opts: SandboxOpts) {
  if (subcommand === "collect") return sandboxCollectCommand(opts);
  if (subcommand === "status") return sandboxStatusCommand(opts);

  if (!VALID_COMMANDS.includes(subcommand as SandboxSubcommand)) {
    console.error(`Unknown sandbox subcommand: ${subcommand}`);
    console.error(`Valid commands: ${VALID_COMMANDS.join(", ")}, collect, status`);
    process.exit(1);
  }

  const projectId = resolveProjectId(opts.projectId);
  if (opts.snapshotId && !opts.trustSnapshotId) {
    throw new Error(
      "--snapshot-id restores executable VM state. Re-run without it, or pass --trust-snapshot-id only for snapshots you created in this workspace.",
    );
  }
  const config = buildConfig(subcommand as SandboxSubcommand, projectId, opts);

  // Preflight: fail fast with an actionable message before we spend ~30s
  // on a doomed bootstrap sandbox. The credential brokering path needs
  // both a Vercel auth token (to create the sandbox) and an AI token (to
  // inject into the firewall transform).
  assertSandboxCredential();
  assertAgentCredential(config.agentType, { inSandbox: true });

  console.log(
    `${BOLD}Sandbox${RESET} — ${CYAN}${config.command}${RESET} — ${BOLD}${config.projectId}${RESET}`,
  );
  console.log(`  Sandboxes: ${config.sandboxCount} x ${config.vcpus} vCPUs`);
  if (config.limit) console.log(`  Limit: ${config.limit}`);
  if (config.filter) console.log(`  Filter: ${config.filter}`);
  if (opts.detach) console.log(`  ${CYAN}Detached mode — will exit after dispatch${RESET}`);
  if (config.extraArgs.length > 0) console.log(`  Passthrough: ${config.extraArgs.join(" ")}`);
  console.log();

  const startTime = Date.now();
  const onLog = makeLogger(startTime);

  if (opts.detach) {
    const runId = await launch(config, onLog);
    console.log();
    console.log(`${GREEN}Launched${RESET} run ${BOLD}${runId}${RESET}`);
    console.log(
      `  Status:  ${DIM}pnpm deepsec sandbox status --project-id ${config.projectId} --run-id ${runId}${RESET}`,
    );
    console.log(
      `  Collect: ${DIM}pnpm deepsec sandbox collect --project-id ${config.projectId} --run-id ${runId}${RESET}`,
    );
    return;
  }

  const results = await orchestrate(config, onLog);
  printResults(results, startTime);
}

async function sandboxCollectCommand(opts: SandboxOpts) {
  const projectId = resolveProjectId(opts.projectId);
  if (!opts.runId) {
    console.log(`Use --run-id to specify which run to collect. Available runs:`);
    await checkStatus(projectId, undefined, console.log);
    return;
  }

  console.log(`${BOLD}Sandbox Collect${RESET} — ${BOLD}${projectId}${RESET} — run ${opts.runId}`);
  console.log();

  const startTime = Date.now();
  const results = await collect(projectId, opts.runId, makeLogger(startTime));
  printResults(results, startTime);
}

async function sandboxStatusCommand(opts: SandboxOpts) {
  const projectId = resolveProjectId(opts.projectId);
  await checkStatus(projectId, opts.runId, console.log);
}

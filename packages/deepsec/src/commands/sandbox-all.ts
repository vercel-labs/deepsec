import fs from "node:fs";
import path from "node:path";
import { getDataRoot, readProjectConfig } from "@deepsec/core";
import { defaultModelForAgent } from "../agent-defaults.js";
import { BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW } from "../formatters.js";
import {
  applyConfiguredModelRoute,
  assertAgentCredential,
  assertSandboxCredential,
} from "../preflight.js";
import { resolveAgentType } from "../resolve-agent-type.js";
import { orchestrate } from "../sandbox/orchestrator.js";
import { partitionFiles } from "../sandbox/partitioner.js";
import type { SandboxConfig, SandboxSubcommand } from "../sandbox/types.js";
import { extractReinvestigate } from "./sandbox-process.js";

// Mirror of VALID_COMMANDS in sandbox-process.ts. Kept in sync by hand —
// `enrich` is intentionally excluded: it runs locally (git committer
// lookups, ownership-plugin RPC) and the worker env-forwarding path that
// used to cover its credentials no longer exists, so a sandboxed enrich
// would run half-configured rather than fail clearly.
const VALID_COMMANDS: ReadonlySet<SandboxSubcommand> = new Set([
  "process",
  "revalidate",
  "triage",
  "scan",
  "report",
]);

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

function discoverProjects(): string[] {
  const dataDir = path.resolve(getDataRoot());
  if (!fs.existsSync(dataDir)) return [];
  return fs
    .readdirSync(dataDir, { withFileTypes: true })
    .filter((e) => e.isDirectory() && fs.existsSync(path.join(dataDir, e.name, "project.json")))
    .map((e) => e.name);
}

function countEligibleFiles(
  projectId: string,
  command: SandboxSubcommand,
  passthrough: string[],
): number {
  const result = partitionFiles(projectId, 1, {
    command,
    limit: undefined,
    filter: extractFlag(passthrough, "--filter"),
    reinvestigate: extractReinvestigate(passthrough) ?? false,
    force: hasFlag(passthrough, "--force"),
    minSeverity:
      extractFlag(passthrough, "--min-severity") ?? extractFlag(passthrough, "--severity"),
  });
  return result.totalFiles;
}

export async function sandboxAllCommand(
  subcommand: string,
  opts: {
    sandboxes?: number;
    vcpus?: number;
    timeout?: number;
    detach?: boolean;
    args?: string[];
  },
) {
  if (!VALID_COMMANDS.has(subcommand as SandboxSubcommand)) {
    console.error(`Unknown sandbox-all subcommand: ${subcommand}`);
    console.error(`Valid commands: ${Array.from(VALID_COMMANDS).join(", ")}`);
    if (subcommand === "enrich") {
      console.error(
        `  enrich runs locally (git history + ownership lookups) and is not sandboxed.\n` +
          `  Run \`deepsec enrich --project-id <id>\` directly instead.`,
      );
    }
    process.exit(1);
  }
  const command = subcommand as SandboxSubcommand;
  const passthrough = opts.args ?? [];
  const totalSandboxes = opts.sandboxes ?? 10;
  const concurrency = parseInt(extractFlag(passthrough, "--concurrency") ?? "4", 10) || 4;
  const vcpus = opts.vcpus ?? Math.min(Math.ceil(concurrency / 2) * 2, 8);
  const timeout = opts.timeout ?? 5 * 60 * 60 * 1000;
  const agentType = resolveAgentType(extractFlag(passthrough, "--agent"));
  const explicitAiApiKeyEnv = extractFlag(passthrough, "--ai-api-key-env");
  const explicitAiBaseUrl = extractFlag(passthrough, "--ai-base-url");
  const resolvedRoute =
    !explicitAiApiKeyEnv && !explicitAiBaseUrl
      ? await applyConfiguredModelRoute(agentType, process.env, { inSandbox: true })
      : undefined;

  // Same preflight as sandbox-process — fail fast before fanning out.
  assertSandboxCredential();
  assertAgentCredential(agentType, {
    inSandbox: true,
    aiApiKeyEnv: explicitAiApiKeyEnv,
  });

  console.log(`${BOLD}Sandbox All${RESET} — ${CYAN}${command}${RESET}`);
  console.log(`  Total sandboxes: ${totalSandboxes}`);
  console.log(`  vCPUs per sandbox: ${vcpus}`);
  if (passthrough.length > 0) console.log(`  Passthrough: ${passthrough.join(" ")}`);
  console.log();

  // Discover projects and count eligible files
  const projects = discoverProjects();
  console.log(`Found ${projects.length} projects. Counting eligible files...`);

  const projectFiles: { projectId: string; files: number }[] = [];
  for (const projectId of projects) {
    try {
      readProjectConfig(projectId); // validate it exists
      const files = countEligibleFiles(projectId, command, passthrough);
      if (files > 0) {
        projectFiles.push({ projectId, files });
        console.log(`  ${projectId}: ${files} files`);
      } else {
        console.log(`  ${DIM}${projectId}: 0 files (skipping)${RESET}`);
      }
    } catch {
      console.log(`  ${DIM}${projectId}: error reading config (skipping)${RESET}`);
    }
  }

  const totalFiles = projectFiles.reduce((s, p) => s + p.files, 0);
  if (totalFiles === 0) {
    console.log("\nNo eligible files across any project.");
    return;
  }

  // Sandbox runs are billed; "give every eligible project one sandbox" must
  // never push us past the user-supplied budget. If there are more eligible
  // projects than `--sandboxes`, take the top-N by file count and tell the
  // user what we dropped.
  if (projectFiles.length > totalSandboxes) {
    projectFiles.sort((a, b) => b.files - a.files);
    const kept = projectFiles.slice(0, totalSandboxes);
    const dropped = projectFiles.slice(totalSandboxes);
    console.log(
      `\n${YELLOW}Budget ${totalSandboxes} < ${projectFiles.length} eligible projects — dropping ${dropped.length}:${RESET}`,
    );
    for (const d of dropped) {
      console.log(`  ${DIM}${d.projectId}: ${d.files} files (skipped — raise --sandboxes)${RESET}`);
    }
    projectFiles.length = 0;
    projectFiles.push(...kept);
  }

  // Allocate sandboxes proportionally by file count (min 1 per project).
  // Invariant: sum(allocations[].sandboxes) === totalSandboxes; the
  // first-pass loop now consumes at most totalSandboxes seats because the
  // length cap above guarantees projectFiles.length <= totalSandboxes.
  const allocations: { projectId: string; sandboxes: number; files: number }[] = [];
  let remaining = totalSandboxes;

  // First pass: give each project at least 1
  for (const p of projectFiles) {
    allocations.push({ projectId: p.projectId, sandboxes: 1, files: p.files });
    remaining--;
  }

  // Second pass: distribute remaining proportionally
  if (remaining > 0) {
    const _weights = projectFiles.map((p) => p.files / totalFiles);
    for (let i = 0; i < remaining; i++) {
      // Find the project with the worst ratio (most files per sandbox)
      let worstIdx = 0;
      let worstRatio = 0;
      for (let j = 0; j < allocations.length; j++) {
        const ratio = allocations[j].files / allocations[j].sandboxes;
        if (ratio > worstRatio) {
          worstRatio = ratio;
          worstIdx = j;
        }
      }
      allocations[worstIdx].sandboxes++;
    }
  }

  console.log(
    `\n${BOLD}Allocation:${RESET} ${totalFiles} files across ${totalSandboxes} sandboxes`,
  );
  for (const a of allocations) {
    const filesPerSandbox = Math.ceil(a.files / a.sandboxes);
    console.log(`  ${a.projectId}: ${a.sandboxes} sandbox(es) × ~${filesPerSandbox} files`);
  }
  console.log();

  const startTime = Date.now();
  const makeLogger = (projectId: string) => (msg: string) => {
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(0);
    console.log(`${DIM}[${elapsed}s]${RESET} ${CYAN}[${projectId}]${RESET} ${msg}`);
  };

  // Run all projects in parallel
  const promises = allocations.map(async (a) => {
    const config: SandboxConfig = {
      projectId: a.projectId,
      command,
      sandboxCount: a.sandboxes,
      vcpus,
      limit: undefined,
      concurrency,
      batchSize: parseInt(extractFlag(passthrough, "--batch-size") ?? "5", 10) || 5,
      agentType,
      aiApiKeyEnv: explicitAiApiKeyEnv,
      aiBaseUrl: explicitAiBaseUrl ?? resolvedRoute?.route.baseUrl,
      brokeredModelCredential: resolvedRoute?.broker,
      model: extractFlag(passthrough, "--model") ?? defaultModelForAgent(agentType),
      snapshotId: undefined,
      saveSnapshot: false,
      keepAlive: false,
      reinvestigate: extractReinvestigate(passthrough) ?? false,
      force: hasFlag(passthrough, "--force"),
      minSeverity:
        extractFlag(passthrough, "--min-severity") ?? extractFlag(passthrough, "--severity"),
      filter: extractFlag(passthrough, "--filter"),
      matchers: extractFlag(passthrough, "--matchers"),
      timeout,
      extraArgs: passthrough,
    };

    try {
      const results = await orchestrate(config, makeLogger(a.projectId));
      const succeeded = results.filter((r) => r.success).length;
      const failed = results.filter((r) => !r.success).length;
      return { projectId: a.projectId, succeeded, failed, total: results.length };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      makeLogger(a.projectId)(`Fatal: ${msg}`);
      return { projectId: a.projectId, succeeded: 0, failed: a.sandboxes, total: a.sandboxes };
    }
  });

  const results = await Promise.all(promises);

  // Summary
  const elapsed = ((Date.now() - startTime) / 1000 / 60).toFixed(1);
  console.log();
  console.log(`${BOLD}Results (${elapsed} min):${RESET}`);
  let totalSucceeded = 0;
  let totalFailed = 0;
  for (const r of results) {
    const icon = r.failed === 0 ? GREEN : r.succeeded === 0 ? RED : "";
    console.log(
      `  ${icon}${r.projectId}${RESET}: ${r.succeeded}/${r.total} sandboxes succeeded${r.failed > 0 ? `, ${r.failed} failed` : ""}`,
    );
    totalSucceeded += r.succeeded;
    totalFailed += r.failed;
  }
  console.log(
    `\n${BOLD}Total:${RESET} ${totalSucceeded} succeeded, ${totalFailed} failed across ${results.length} projects`,
  );
}

import { config as dotenvConfig } from "dotenv";

dotenvConfig({ path: ".env.local" });
dotenvConfig(); // also load .env as fallback

import { getRegistry } from "@deepsec/core";
import { setAttributionVersion } from "@deepsec/processor";
import { Command } from "commander";
import { collectRepeatable } from "./agent-config.js";
import { enrichCommand } from "./commands/enrich.js";
import { exportCommand } from "./commands/export.js";
import { initCommand } from "./commands/init.js";
import { initProjectCommand } from "./commands/init-project.js";
import { metricsCommand } from "./commands/metrics.js";
import { processCommand } from "./commands/process.js";
import { reportCommand } from "./commands/report.js";
import { revalidateCommand } from "./commands/revalidate.js";
import { sandboxAllCommand } from "./commands/sandbox-all.js";
import { sandboxCommand } from "./commands/sandbox-process.js";
import { scanCommand } from "./commands/scan.js";
import { setupCommand } from "./commands/setup.js";
import { statusCommand } from "./commands/status.js";
import { triageCommand } from "./commands/triage.js";
import { loadConfig } from "./load-config.js";
import { installSandboxOutputCap } from "./output-cap.js";
import { applyAiGatewayDefaults } from "./preflight.js";
import { modelRouteFromCli } from "./setup/options.js";
import {
  formatSetupDocumentationHuman,
  formatSetupErrorHuman,
  outputModeFromArgv,
  SetupProtocolError,
  setupErrorExitCode,
  setupErrorPayload,
} from "./setup/protocol.js";
import { getDeepsecVersion } from "./version.js";

installSandboxOutputCap();

const program = new Command();

function parsePackageManager(value: string): "pnpm" | "npm" {
  if (value !== "pnpm" && value !== "npm") {
    throw new Error("--package-manager must be pnpm or npm");
  }
  return value;
}

function parseSetupThrough(
  value: string,
): "install" | "login" | "threat-model" | "coverage" | "process" {
  if (["install", "login", "threat-model", "coverage", "process"].includes(value)) {
    return value as "install" | "login" | "threat-model" | "coverage" | "process";
  }
  throw new Error("--through must be install, login, threat-model, coverage, or process");
}

function parsePositiveNumber(value: string): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) throw new Error("Value must be a positive number");
  return parsed;
}

function parseDuration(value: string): number {
  const match = /^(\d+(?:\.\d+)?)(ms|s|m|h)$/.exec(value);
  if (!match) throw new Error("Duration must look like 500ms, 30s, 10m, or 2h");
  const multipliers = { ms: 1, s: 1_000, m: 60_000, h: 3_600_000 } as const;
  return Number(match[1]) * multipliers[match[2] as keyof typeof multipliers];
}

program
  .name("deepsec")
  .description("AI-powered vulnerability scanner for any codebase")
  .version(getDeepsecVersion())
  .addHelpText(
    "after",
    `
Quickstart:
  cd <your-repo>                 first, in the codebase you want to scan
  npx deepsec init               install, connect, model, scan, process

  See \`deepsec init --help\` and the docs at:
    https://github.com/vercel/deepsec`,
  );

program
  .command("init [workspace] [target-root]")
  .description("Create and fully set up a resumable .deepsec workspace")
  .option("--id <project-id>", "Override the project id (default: basename of <target-root>)")
  .option("--force", "Allow writing into a non-empty workspace directory")
  .option("--plan", "Inspect the setup plan without writing files or running setup")
  .option("--scaffold-only", "Only create files; do not install, connect, scan, or process")
  .option("--skip-install", "Require dependencies to exist instead of running pnpm/npm install")
  .option("--package-manager <name>", "Installer to use: pnpm or npm", parsePackageManager)
  .option("--agent <type>", "AI agent: codex, claude, or pi")
  .option("--model <model>", "Model for repository analysis and processing")
  .option("--model-profile <profile>", "Benchmark profile: best, value, or budget")
  .option("--thinking-level <level>", "Reasoning effort: minimal, low, medium, high, or xhigh")
  .option("--model-auth <mode>", "Credential route: gateway, direct, custom, or local")
  .option("--ai-provider <provider>", "Provider for direct/custom credentials")
  .option("--ai-api-key-env <name>", "Environment variable containing a direct/custom API key")
  .option("--ai-base-url <url>", "Direct/custom provider base URL")
  .option("--ai-credential-header <name[:scheme]>", "Custom auth header; scheme is bearer or raw")
  .option("--headless", "Never prompt or open an interactive login (automatic without a TTY)")
  .option("--non-interactive", "Legacy alias for --headless")
  .option("--yes", "Accept deterministic headless defaults and dedicated-project creation")
  .option("--vercel-team-id <id>", "Vercel team id (non-interactive override)")
  .option("--vercel-project-id <id>", "Vercel project id (non-interactive override)")
  .option("--vercel-project-name <name>", "Deterministic dedicated project name override")
  .option("--concurrency <n>", "AI processing batches to run in parallel", parseInt)
  .option(
    "--through <phase>",
    "Stop after install, login, threat-model, coverage, or process",
    parseSetupThrough,
  )
  .option(
    "--max-cost-usd <n>",
    "Stop AI processing at a resumable cost boundary",
    parsePositiveNumber,
  )
  .option("--max-duration <duration>", "Stop setup at a resumable duration boundary", parseDuration)
  .option("--no-tui", "Use stable line-oriented output instead of the interactive dashboard")
  .option("--output <mode>", "Output mode: human, json, or jsonl", "human")
  .addHelpText(
    "after",
    `
Defaults:
  workspace     .deepsec
  target-root   .              (the codebase you ran init from)
  project id    derived from the target's directory basename
  model route   Vercel AI Gateway via the exact linked workspace

The normal flow also keeps Sandbox credentials in scope, writes INFO.md plus a
surface inventory, checks scan coverage, safely generates narrow matchers when
needed, and starts processing. Re-run the command to resume from checkpoints.

Examples:
  $ npx deepsec init                          # most common — from your repo root
  $ npx deepsec init --plan --output json     # read-only agent/CI plan
  $ npx deepsec init --yes --model-profile value --output jsonl
  $ npx deepsec init --scaffold-only          # files only; manual legacy flow
  $ npx deepsec init --package-manager npm    # use npm in the isolated workspace
  $ MY_KEY=... npx deepsec init --agent codex --model-auth direct --ai-provider openai --ai-api-key-env MY_KEY
  $ npx deepsec init --model-auth local       # machine-wide claude/codex logins; no API key
  $ npx deepsec init audits ../my-app         # custom workspace + target
  $ npx deepsec init .deepsec . --id my-app   # override the auto-derived id`,
  )
  .action(
    (workspace: string | undefined, targetRoot: string | undefined, opts: Record<string, any>) =>
      initCommand({
        workspace,
        targetRoot,
        id: opts.id,
        force: opts.force,
        plan: opts.plan,
        scaffoldOnly: opts.scaffoldOnly,
        skipInstall: opts.skipInstall,
        packageManager: opts.packageManager,
        agent: opts.agent,
        model: opts.model,
        modelProfile: opts.modelProfile,
        thinkingLevel: opts.thinkingLevel,
        modelRoute:
          opts.modelAuth || opts.aiProvider || opts.aiApiKeyEnv || opts.aiBaseUrl
            ? modelRouteFromCli(opts)
            : undefined,
        headless: opts.headless,
        nonInteractive: opts.nonInteractive,
        yes: opts.yes,
        teamId: opts.vercelTeamId,
        vercelProjectId: opts.vercelProjectId,
        vercelProjectName: opts.vercelProjectName,
        concurrency: opts.concurrency,
        through: opts.through,
        maxCostUsd: opts.maxCostUsd,
        maxDurationMs: opts.maxDuration,
        noTui: opts.tui === false,
        output: opts.output,
      }),
  );

program
  .command("setup")
  .description("Resume or reconcile the one-shot setup workflow")
  .option("--project-id <id>", "Project identifier (auto-resolved for a single project)")
  .option("--root <path>", "Override the configured project root")
  .option("--status", "Show resumable phase status without running setup")
  .option("--skip-install", "Require dependencies to exist instead of running pnpm/npm install")
  .option("--package-manager <name>", "Installer to use: pnpm or npm", parsePackageManager)
  .option("--agent <type>", "AI agent: codex, claude, or pi")
  .option("--model <model>", "Model for repository analysis and processing")
  .option("--model-profile <profile>", "Benchmark profile: best, value, or budget")
  .option("--thinking-level <level>", "Reasoning effort: minimal, low, medium, high, or xhigh")
  .option("--model-auth <mode>", "Credential route: gateway, direct, custom, or local")
  .option("--ai-provider <provider>", "Provider for direct/custom credentials")
  .option("--ai-api-key-env <name>", "Environment variable containing a direct/custom API key")
  .option("--ai-base-url <url>", "Direct/custom provider base URL")
  .option("--ai-credential-header <name[:scheme]>", "Custom auth header; scheme is bearer or raw")
  .option("--headless", "Never prompt or open an interactive login (automatic without a TTY)")
  .option("--non-interactive", "Legacy alias for --headless")
  .option("--yes", "Accept deterministic headless defaults and dedicated-project creation")
  .option("--vercel-team-id <id>", "Vercel team id (non-interactive override)")
  .option("--vercel-project-id <id>", "Vercel project id (non-interactive override)")
  .option("--vercel-project-name <name>", "Deterministic dedicated project name override")
  .option("--concurrency <n>", "AI processing batches to run in parallel", parseInt)
  .option(
    "--through <phase>",
    "Stop after install, login, threat-model, coverage, or process",
    parseSetupThrough,
  )
  .option(
    "--max-cost-usd <n>",
    "Stop AI processing at a resumable cost boundary",
    parsePositiveNumber,
  )
  .option("--max-duration <duration>", "Stop setup at a resumable duration boundary", parseDuration)
  .option("--no-tui", "Use stable line-oriented output instead of the interactive dashboard")
  .option("--output <mode>", "Output mode: human, json, or jsonl", "human")
  .addHelpText(
    "after",
    `
Without model-route flags, setup preserves the route stored in
deepsec.config.ts. It checks required outputs and resumes at the first stale,
missing, errored, or incomplete phase.

Examples:
  $ pnpm deepsec setup
  $ pnpm deepsec setup --status --output json
  $ pnpm deepsec setup --project-id api
  $ MY_KEY=... pnpm deepsec setup --agent codex --model-auth direct --ai-provider openai --ai-api-key-env MY_KEY`,
  )
  .action(setupCommand);

program
  .command("init-project <target-root>")
  .description("Register an additional project in the current .deepsec workspace")
  .option("--id <project-id>", "Override the project id (default: basename of <target-root>)")
  .option("--force", "Overwrite an existing project of the same id")
  .addHelpText(
    "after",
    `
Run from inside a .deepsec/ workspace. Appends an entry to
deepsec.config.ts (above the marker comment) and writes a fresh
data/<id>/{INFO.md,SETUP.md,project.json}.
Run \`pnpm deepsec setup --project-id <id>\` afterward to perform repository
analysis, coverage-guided scanning, and processing for the new project.

Examples:
  $ pnpm deepsec init-project ../another-app
  $ pnpm deepsec init-project ./packages/api --id api`,
  )
  .action((targetRoot: string | undefined, opts: { id?: string; force?: boolean }) =>
    initProjectCommand({ targetRoot, id: opts.id, force: opts.force }),
  );

program
  .command("scan")
  .description("Run regex matchers across a project to find candidate vulnerability sites")
  .option(
    "--project-id <id>",
    "Project identifier (default: the only project in deepsec.config.ts; required if there are multiple)",
  )
  .option(
    "--root <path>",
    "Override the project's root (rare — use only for sandbox runs or one-off scans against a different checkout)",
  )
  .option(
    "--matchers <slugs>",
    "Comma-separated matcher slugs to run (default: all registered matchers)",
  )
  .addHelpText(
    "after",
    `
The root is resolved from deepsec.config.ts (or data/<id>/project.json
once a project has been scanned). Pass --root only when overriding.

Examples:
  $ pnpm deepsec scan --project-id my-app
  $ pnpm deepsec scan --project-id my-app --matchers auth-bypass,xss
  $ pnpm deepsec scan --project-id my-app --root ../checkout-on-pr-branch`,
  )
  .action(scanCommand);

program
  .command("process")
  .description("Investigate candidates with an AI agent")
  .option(
    "--project-id <id>",
    "Project identifier (default: the only project in deepsec.config.ts; required if there are multiple)",
  )
  .option("--run-id <id>", "Resume a specific processing run")
  .option(
    "--agent <type>",
    "Agent plugin type: codex, claude, or pi (default: defaultAgent in deepsec.config.ts, else codex)",
  )
  .option(
    "--model <model>",
    "Model to use (default: claude-opus-4-8 for claude, gpt-5.5 for codex, zai/glm-5.2 for pi)",
  )
  .option(
    "--ai-provider <provider>",
    "Pi: provider to override for --ai-base-url / --ai-api-key-env (e.g. openai)",
  )
  .option(
    "--ai-base-url <url>",
    "Pi: provider base URL override (e.g. a Martian/OpenAI-compatible gateway)",
  )
  .option("--ai-api-key-env <name>", "Pi: environment variable that holds the provider API key")
  .option(
    "--ai-header <name=value>",
    "Pi: extra provider request header; repeatable",
    collectRepeatable,
    [],
  )
  .option("--max-turns <n>", "Max conversation turns per batch (default: 150)", parseInt)
  .option(
    "--thinking-level <level>",
    "Reasoning/thinking effort for the main agent run: minimal, low, medium, high, or xhigh (default: xhigh)",
  )
  .option(
    "--reinvestigate [n]",
    "Re-investigate files. No arg = all files. Pass N as a wave marker — productive analyses are tagged with N, and re-running with the same N skips already-done files. Bump N to request another pass.",
  )
  .option("--limit <n>", "Max number of files to process", parseInt)
  .option("--concurrency <n>", "Batches to process in parallel (default: cores - 1)", parseInt)
  .option("--filter <prefix>", "Only process files matching this path prefix")
  .option("--batch-size <n>", "Files per batch (default: 5)", parseInt)
  .option("--root <path>", "Override rootPath from project.json (for sandbox execution)")
  .option(
    "--manifest <path>",
    "JSON file with array of file paths to process (instead of all pending)",
  )
  .option("--only-slugs <csv>", "Only process files that have a candidate with one of these slugs")
  .option("--skip-slugs <csv>", "Skip files whose candidate slugs are all in this set")
  .option(
    "--diff <ref>",
    "Direct mode: investigate files changed between <ref> and HEAD (e.g. origin/main, HEAD~1..HEAD). Auto-creates the project if needed. Exits 1 if any finding is produced.",
  )
  .option("--diff-staged", "Direct mode: investigate files in the git index (vs HEAD)")
  .option("--diff-working", "Direct mode: investigate uncommitted + untracked files")
  .option("--files <csv>", "Direct mode: investigate this comma-separated path list")
  .option(
    "--files-from <path>",
    "Direct mode: read newline-delimited paths from <path> (or '-' for stdin)",
  )
  .option("--no-ignore", "In direct mode, skip the default ignore filter (test files, dist, etc.)")
  .option(
    "--comment-out <path>",
    "Write a PR-comment-shaped markdown summary to <path> (only when findings exist)",
  )
  .action(processCommand);

program
  .command("report")
  .description("Generate a markdown + JSON report from current analysis state.")
  .option(
    "--project-id <id>",
    "Project identifier (default: the only project in deepsec.config.ts; required if there are multiple)",
  )
  .option("--run-id <id>", "Filter to a specific run's results")
  .action(reportCommand);

program
  .command("revalidate")
  .description("Re-check existing findings for false positives")
  .option(
    "--project-id <id>",
    "Project identifier (default: the only project in deepsec.config.ts; required if there are multiple)",
  )
  .option("--run-id <id>", "Resume a specific revalidation run")
  .option(
    "--agent <type>",
    "Agent plugin type: codex, claude, or pi (default: defaultAgent in deepsec.config.ts, else codex)",
  )
  .option(
    "--model <model>",
    "Model to use (default: claude-opus-4-8 for claude, gpt-5.5 for codex, zai/glm-5.2 for pi)",
  )
  .option(
    "--ai-provider <provider>",
    "Pi: provider to override for --ai-base-url / --ai-api-key-env (e.g. openai)",
  )
  .option(
    "--ai-base-url <url>",
    "Pi: provider base URL override (e.g. a Martian/OpenAI-compatible gateway)",
  )
  .option("--ai-api-key-env <name>", "Pi: environment variable that holds the provider API key")
  .option(
    "--ai-header <name=value>",
    "Pi: extra provider request header; repeatable",
    collectRepeatable,
    [],
  )
  .option("--max-turns <n>", "Max conversation turns per batch (default: 150)", parseInt)
  .option(
    "--thinking-level <level>",
    "Reasoning/thinking effort for the main agent run: minimal, low, medium, high, or xhigh (default: xhigh)",
  )
  .option(
    "--min-severity <sev>",
    "Only revalidate findings at this severity or above (CRITICAL, HIGH, MEDIUM, HIGH_BUG, BUG)",
  )
  .option("--force", "Re-check already-validated findings")
  .option("--limit <n>", "Max files to revalidate", parseInt)
  .option("--concurrency <n>", "Parallel batches (default: cores - 1)", parseInt)
  .option("--batch-size <n>", "Files per revalidation batch (default: 5)", parseInt)
  .option("--filter <prefix>", "Only revalidate files matching path prefix")
  .option("--root <path>", "Override rootPath from project.json (for sandbox execution)")
  .option("--manifest <path>", "JSON file with array of file paths to revalidate")
  .option("--only-slugs <csv>", "Only revalidate findings with one of these vulnSlugs")
  .option("--skip-slugs <csv>", "Skip findings with any of these vulnSlugs")
  .action(revalidateCommand);

program
  .command("enrich")
  .description("Enrich files with git history + ownership oracle")
  .option(
    "--project-id <id>",
    "Project identifier (default: the only project in deepsec.config.ts; required if there are multiple)",
  )
  .option("--filter <prefix>", "Only enrich files matching path prefix")
  .option(
    "--min-severity <sev>",
    "Only enrich files with a finding at this severity or above (CRITICAL, HIGH, MEDIUM, HIGH_BUG, BUG, LOW)",
  )
  .option("--force", "Re-enrich already-enriched files")
  .option("--concurrency <n>", "Parallel ownership oracle requests (default: cores - 1)", parseInt)
  .action(enrichCommand);

program
  .command("triage")
  .description("Classify findings by priority (P0/P1/P2/skip) — lightweight, no code reading")
  .option(
    "--project-id <id>",
    "Project identifier (default: the only project in deepsec.config.ts; required if there are multiple)",
  )
  .option("--severity <sev>", "Severity to triage (default: MEDIUM)", "MEDIUM")
  .option("--model <model>", "Model to use (default: claude-sonnet-4-6 — cheaper)")
  .option("--force", "Re-triage already-triaged findings")
  .option("--limit <n>", "Max findings to triage", parseInt)
  .option("--concurrency <n>", "Parallel triage batches (default: cores - 1)", parseInt)
  .action(triageCommand);

program
  .command("status")
  .description("Show current state of the project mirror")
  .option(
    "--project-id <id>",
    "Project identifier (default: the only project in deepsec.config.ts; required if there are multiple)",
  )
  .action(statusCommand);

program
  .command("export")
  .description("Export findings as JSON or as a directory of per-finding markdown files")
  .option("--format <kind>", "Output format: json (default) or md-dir", "json")
  .option("--project-id <csv>", "Comma-separated project IDs (omit for all)")
  .option(
    "--min-severity <sev>",
    "Only export findings at this severity or above (CRITICAL, HIGH, MEDIUM, HIGH_BUG, BUG, LOW)",
  )
  .option(
    "--only-severity <sev>",
    "Only export findings at this exact severity (CRITICAL, HIGH, MEDIUM, HIGH_BUG, BUG, LOW)",
  )
  .option("--discovered-today", "Only findings whose most recent analysis was today (local time)")
  .option(
    "--since <iso>",
    "Only findings whose most recent analysis was on/after this ISO timestamp",
  )
  .option("--only-true-positive", "Only findings revalidated as true-positive")
  .option(
    "--include-resolved",
    "Include findings revalidated as fixed / false-positive / accepted-risk (hidden by default)",
  )
  .option(
    "--exclude-false-positive",
    "Deprecated — false-positive is now hidden by default; this flag is a no-op",
  )
  .option("--only-slugs <csv>", "Only export findings with these vulnSlugs")
  .option("--skip-slugs <csv>", "Drop findings with these vulnSlugs")
  .option("--require-owner", "Drop findings that have no ownership data (no assignee, no teams)")
  .option(
    "--only-agent <type>",
    "Only export findings produced by this agent backend (e.g. codex, claude, pi)",
  )
  .option(
    "--only-marker <n>",
    "Only export findings produced under this --reinvestigate wave marker",
  )
  .option(
    "--out <path>",
    "Output path. JSON format: file (default: stdout). md-dir format: directory (required).",
  )
  .action(exportCommand);

program
  .command("metrics")
  .description("Report findings metrics across all projects (or one project)")
  .option("--project-id <id>", "Project identifier (omit for all projects)")
  .option("--min-severity <sev>", "Minimum severity to include (default: LOW)")
  .action(metricsCommand);

const sandboxCmd = program
  .command("sandbox <command>")
  .description(
    "Run a deepsec command on Vercel Sandbox microVMs. Sandbox-level options (--sandboxes, --vcpus, --detach, etc.) are parsed; all other options are passed through to the subcommand.",
  )
  .allowUnknownOption()
  .allowExcessArguments(true)
  .option(
    "--project-id <id>",
    "Project identifier (default: the only project in deepsec.config.ts; required if there are multiple)",
  )
  .option("--sandboxes <n>", "Number of parallel sandboxes (default: 1)", parseInt)
  .option("--vcpus <n>", "vCPUs per sandbox (default: 2, max: 8)", parseInt)
  .option("--detach", "Launch sandboxes and exit immediately (collect results later)")
  .option("--run-id <id>", "Run ID for status/collect commands")
  .option("--snapshot-id <id>", "Restore from existing snapshot")
  .option("--save-snapshot", "Snapshot after setup for future reuse")
  .option("--keep-alive", "Don't stop sandboxes after completion")
  .option("--timeout <ms>", "Sandbox timeout in ms (default: 5 hours)", parseInt)
  .action((subcommand: string, opts: Record<string, unknown>) => {
    // Commander puts unknown options into .args on the Command object
    const unknownArgs = sandboxCmd.args.slice(1); // skip the subcommand itself
    return sandboxCommand(subcommand, { ...opts, args: unknownArgs } as Parameters<
      typeof sandboxCommand
    >[1]);
  });

const sandboxAllCmd = program
  .command("sandbox-all <command>")
  .description(
    "Run a deepsec command across ALL projects on Vercel Sandbox microVMs, allocating sandboxes proportionally",
  )
  .allowUnknownOption()
  .allowExcessArguments(true)
  .option("--sandboxes <n>", "Total sandboxes to distribute (default: 10)", parseInt)
  .option("--vcpus <n>", "vCPUs per sandbox (default: auto from concurrency, max: 8)", parseInt)
  .option("--timeout <ms>", "Sandbox timeout in ms (default: 5 hours)", parseInt)
  .action((subcommand: string, opts: Record<string, unknown>) => {
    const unknownArgs = sandboxAllCmd.args.slice(1);
    return sandboxAllCommand(subcommand, { ...opts, args: unknownArgs } as Parameters<
      typeof sandboxAllCommand
    >[1]);
  });

/**
 * Surface error messages cleanly. Stack traces are noise for user-facing
 * failures (bad input, missing config, network errors). Set
 * `DEEPSEC_DEBUG=1` to see them when debugging.
 */
function printFatal(err: unknown): never {
  const outputMode = outputModeFromArgv();
  if (outputMode === "json" || outputMode === "jsonl") {
    console.log(JSON.stringify(setupErrorPayload(err)));
    process.exit(setupErrorExitCode(err));
  }
  const verbose = process.env.DEEPSEC_DEBUG === "1";
  console.error(
    `\n${err instanceof SetupProtocolError ? formatSetupErrorHuman(err) : err instanceof Error ? err.message : err}`,
  );
  if (!(err instanceof SetupProtocolError)) {
    const documentation = formatSetupDocumentationHuman();
    if (documentation) console.error(`\n${documentation}`);
  }
  if (verbose && err instanceof Error && err.stack) {
    console.error(err.stack);
  } else if (!verbose && !(err instanceof SetupProtocolError)) {
    console.error("\n(set DEEPSEC_DEBUG=1 for a stack trace)");
  }
  process.exit(setupErrorExitCode(err));
}

process.on("unhandledRejection", printFatal);
process.on("uncaughtException", printFatal);

async function main() {
  // Stamp the running CLI version into the AI Gateway App Attribution
  // title (x-title: deepsec/<version>) before any agent is constructed.
  setAttributionVersion(getDeepsecVersion());
  // Expand AI_GATEWAY_API_KEY (or fall back to a Vercel OIDC token) into
  // the per-SDK env vars before any command handler instantiates an agent.
  // Must run before loadConfig in case the user's deepsec.config.ts reads
  // these vars at module load.
  await applyAiGatewayDefaults();
  await loadConfig();
  // Plugins may register their own subcommands.
  for (const register of getRegistry().commands) {
    register(program);
  }
  await program.parseAsync();
}

main();

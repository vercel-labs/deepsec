import { config as dotenvConfig } from "dotenv";

dotenvConfig({ path: ".env.local" });
dotenvConfig(); // also load .env as fallback

import { getRegistry } from "@deepsec/core";
import { Command } from "commander";
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
import { statusCommand } from "./commands/status.js";
import { triageCommand } from "./commands/triage.js";
import { loadConfig } from "./load-config.js";

const program = new Command();

program
  .name("deepsec")
  .description("AI-powered vulnerability scanner for any codebase")
  .version("0.1.0")
  .addHelpText(
    "after",
    `
Quickstart:
  cd <your-repo>                 first, in the codebase you want to scan
  npx deepsec init               scaffold .deepsec/ + register this repo
  cd .deepsec && pnpm install
  pnpm deepsec scan    --project-id <id>
  pnpm deepsec process --project-id <id>

  See \`deepsec init --help\` and the docs at:
    https://github.com/vercel/deepsec`,
  );

program
  .command("init [workspace] [target-root]")
  .description("Scaffold .deepsec/ in your repo and register the first project")
  .option("--id <project-id>", "Override the project id (default: basename of <target-root>)")
  .option("--force", "Allow writing into a non-empty workspace directory")
  .addHelpText(
    "after",
    `
Defaults:
  workspace     .deepsec
  target-root   .              (the codebase you ran init from)
  project id    derived from the target's directory basename

Examples:
  $ npx deepsec init                          # most common — from your repo root
  $ npx deepsec init audits ../my-app         # custom workspace + target
  $ npx deepsec init .deepsec . --id my-app   # override the auto-derived id`,
  )
  .action(
    (
      workspace: string | undefined,
      targetRoot: string | undefined,
      opts: { id?: string; force?: boolean },
    ) =>
      initCommand({
        workspace,
        targetRoot,
        id: opts.id,
        force: opts.force,
      }),
  );

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
  .option("--agent <type>", "Agent plugin type (claude-agent-sdk, codex)", "claude-agent-sdk")
  .option(
    "--model <model>",
    "Model to use (default: claude-opus-4-7 for claude-agent-sdk, gpt-5.5 for codex)",
  )
  .option("--max-turns <n>", "Max conversation turns per batch (default: 150)", parseInt)
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
  .option("--agent <type>", "Agent plugin type (claude-agent-sdk, codex)", "claude-agent-sdk")
  .option(
    "--model <model>",
    "Model to use (default: claude-opus-4-7 for claude-agent-sdk, gpt-5.5 for codex)",
  )
  .option("--max-turns <n>", "Max conversation turns per batch (default: 150)", parseInt)
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
  .option("--exclude-false-positive", "Drop findings revalidated as false-positive")
  .option("--only-slugs <csv>", "Only export findings with these vulnSlugs")
  .option("--skip-slugs <csv>", "Drop findings with these vulnSlugs")
  .option("--require-owner", "Drop findings that have no ownership data (no assignee, no teams)")
  .option(
    "--only-agent <type>",
    "Only export findings produced by this agent backend (e.g. codex, claude-agent-sdk)",
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
  const verbose = process.env.DEEPSEC_DEBUG === "1";
  console.error(`\n${err instanceof Error ? err.message : err}`);
  if (verbose && err instanceof Error && err.stack) {
    console.error(err.stack);
  } else if (!verbose) {
    console.error("\n(set DEEPSEC_DEBUG=1 for a stack trace)");
  }
  process.exit(1);
}

process.on("unhandledRejection", printFatal);
process.on("uncaughtException", printFatal);

async function main() {
  await loadConfig();
  // Plugins may register their own subcommands.
  for (const register of getRegistry().commands) {
    register(program);
  }
  await program.parseAsync();
}

main();

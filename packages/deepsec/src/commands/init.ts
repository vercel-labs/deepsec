import fs from "node:fs";
import path from "node:path";
import { ensureProject } from "@deepsec/core";
import {
  type ModelProfile,
  parseModelProfile,
  promptForModelSelection,
  resolveModelProfile,
} from "../auth/model-picker.js";
import type { ModelRoute } from "../auth/model-route.js";
import { promptForModelRoute } from "../auth/model-route-prompt.js";
import { ensureVercelLink, readWorkspaceLink } from "../auth/vercel-link.js";
import { BOLD, CYAN, DIM, GREEN, RESET, YELLOW } from "../formatters.js";
import { requireExistingDir } from "../require-dir.js";
import { validateProjectId } from "../resolve-project-id.js";
import { runSetupWorkflow, type SetupThrough } from "../setup/coordinator.js";
import type { SupportedPackageManager } from "../setup/install.js";
import { shouldUseHeadlessMode } from "../setup/interaction.js";
import { acquireSetupLock } from "../setup/lock.js";
import { persistedModelRoute, recordInitialModelRoute } from "../setup/persisted-route.js";
import { buildSetupPlan } from "../setup/plan.js";
import { deterministicVercelProjectName } from "../setup/project-name.js";
import {
  parseSetupOutputMode,
  type SetupOutputMode,
  SetupProtocolError,
  setSetupDocumentationWorkspace,
} from "../setup/protocol.js";
import { createSetupReporter, printSetupSummary } from "../setup/reporter.js";
import { getDeepsecWorkspaceDependency } from "../version.js";
import { PROJECTS_INSERT_MARKER, registerProject } from "./init-project.js";

const IGNORED_WORKSPACE_ENTRIES = new Set([".git", ".DS_Store"]);

export interface InitOpts {
  workspace?: string;
  targetRoot?: string;
  id?: string;
  force?: boolean;
  scaffoldOnly?: boolean;
  skipInstall?: boolean;
  packageManager?: SupportedPackageManager;
  agent?: string;
  model?: string;
  modelProfile?: ModelProfile | string;
  thinkingLevel?: string;
  modelRoute?: ModelRoute;
  headless?: boolean;
  nonInteractive?: boolean;
  yes?: boolean;
  teamId?: string;
  vercelProjectId?: string;
  vercelProjectName?: string;
  concurrency?: number;
  noTui?: boolean;
  output?: SetupOutputMode | string;
  plan?: boolean;
  through?: SetupThrough;
  maxCostUsd?: number;
  maxDurationMs?: number;
}

export async function initCommand(opts: InitOpts) {
  // Defaults: scaffold `.deepsec/` inside the current codebase, with the
  // codebase itself as the first project. Override either by passing
  // explicit positional args.
  const workspaceArg = opts.workspace ?? ".deepsec";
  const targetArg = opts.targetRoot ?? ".";

  const workspaceDir = path.resolve(process.cwd(), workspaceArg);
  setSetupDocumentationWorkspace(workspaceDir);
  const deepsecDependency = getDeepsecWorkspaceDependency();
  const headless = shouldUseHeadlessMode(opts);
  const outputMode = parseSetupOutputMode(opts.output);
  let targetAbs: string;
  targetAbs = requireExistingDir(targetArg, "<target-root>");

  if (opts.plan) {
    const projectId = validateProjectId(opts.id ?? path.basename(targetAbs));
    const plan = await buildSetupPlan({
      workspaceDir,
      projectRoot: targetAbs,
      projectId,
      packageManager: opts.packageManager,
      modelRoute: opts.modelRoute,
      modelProfile: parseModelProfile(opts.modelProfile),
      model: opts.model,
      agent: opts.agent,
      thinkingLevel: opts.thinkingLevel,
      yes: opts.yes,
      teamId: opts.teamId,
      vercelProjectId: opts.vercelProjectId,
      deterministicProjectName:
        opts.vercelProjectName ?? deterministicVercelProjectName(projectId, targetAbs),
    });
    console.log(JSON.stringify(plan, null, outputMode === "jsonl" ? undefined : 2));
    return;
  }

  let resuming = false;
  if (fs.existsSync(workspaceDir)) {
    const meaningful = fs
      .readdirSync(workspaceDir)
      .filter((e) => !IGNORED_WORKSPACE_ENTRIES.has(e));
    if (meaningful.length > 0) {
      const resumeId = validateProjectId(opts.id ?? path.basename(targetAbs));
      const projectPath = path.join(workspaceDir, "data", resumeId, "project.json");
      resuming =
        fs.existsSync(path.join(workspaceDir, "deepsec.config.ts")) && fs.existsSync(projectPath);
      if (resuming) {
        let registeredRoot: unknown;
        try {
          registeredRoot = JSON.parse(fs.readFileSync(projectPath, "utf8"))?.rootPath;
        } catch {
          if (!opts.force) {
            throw new Error(
              `Project registration is corrupt: ${projectPath}\n` +
                `Rerun with --force to repair this generated file.`,
            );
          }
        }
        if (typeof registeredRoot !== "string" || !registeredRoot) {
          if (!opts.force) {
            throw new Error(
              `Project registration is missing rootPath: ${projectPath}\n` +
                `Rerun with --force to repair this generated file.`,
            );
          }
          const originalCwd = process.cwd();
          try {
            process.chdir(workspaceDir);
            registeredRoot = ensureProject(resumeId, targetAbs).rootPath;
          } finally {
            process.chdir(originalCwd);
          }
        }
        if (typeof registeredRoot !== "string" || !registeredRoot) {
          throw new Error(`Could not repair project registration: ${projectPath}`);
        }
        const canonicalRegisteredRoot = fs.existsSync(registeredRoot)
          ? fs.realpathSync(registeredRoot)
          : path.resolve(registeredRoot);
        if (canonicalRegisteredRoot !== targetAbs) {
          throw new Error(
            `Cannot resume project "${resumeId}" with a different target root.\n` +
              `  Registered: ${canonicalRegisteredRoot}\n` +
              `  Requested:  ${targetAbs}\n` +
              `Use a different workspace or project id for the other checkout.`,
          );
        }
      }
      if (!resuming && !opts.force) {
        throw new Error(
          `Workspace directory is not empty: ${workspaceDir}\n` +
            `Use --force to write into a non-empty directory.`,
        );
      }
    }
  }

  // Workspace skeleton: empty config (with marker), README, AGENTS, env.
  fs.mkdirSync(workspaceDir, { recursive: true });
  writeFile(
    workspaceDir,
    "package.json",
    packageJson(workspacePackageName(workspaceDir), deepsecDependency),
  );
  reconcileLocalDeepsecDependency(workspaceDir, deepsecDependency);
  // Sever .deepsec/ from any ancestor monorepo. npm and yarn walk up looking
  // for a `package.json` with `workspaces` defined; pnpm walks up looking
  // for a `pnpm-workspace.yaml`. Both stop at the first hit, so dropping a
  // pnpm-workspace.yaml here (and an empty `workspaces: []` in package.json,
  // see packageJson()) makes `.deepsec/` its own root regardless of what
  // the parent repo defines. Lets `npm/yarn/pnpm install` from `.deepsec/`
  // manage only this directory's deps.
  writeFile(workspaceDir, "pnpm-workspace.yaml", pnpmWorkspaceYaml());
  writeFile(workspaceDir, "deepsec.config.ts", emptyConfigTs());
  writeFile(workspaceDir, "generated-matchers.ts", generatedMatchersTs());
  writeFile(workspaceDir, "AGENTS.md", workspaceAgentsMd());
  writeFile(workspaceDir, ".gitignore", gitignore());

  // Register the first project via the shared code path. Same writes
  // `init-project` would do: data/<id>/{project.json,INFO.md,SETUP.md}
  // and append to projects[].
  let registered: ReturnType<typeof registerProject>;
  if (resuming) {
    const id = validateProjectId(opts.id ?? path.basename(targetAbs));
    registered = {
      id,
      targetRel: path.relative(workspaceDir, targetAbs).split(path.sep).join("/"),
      targetAbs,
      configPath: path.join(workspaceDir, "deepsec.config.ts"),
      setupMdPath: path.join(workspaceDir, "data", id, "SETUP.md"),
      infoMdPath: path.join(workspaceDir, "data", id, "INFO.md"),
    };
  } else {
    registered = registerProject({
      workspaceDir,
      targetRoot: targetAbs,
      id: opts.id,
      force: opts.force,
    });
  }

  // README references the project, so write it AFTER registration.
  writeFile(workspaceDir, "README.md", readmeMd(registered.id, registered.targetRel));

  const wsRel = path.relative(process.cwd(), workspaceDir) || ".";
  if (!opts.scaffoldOnly) {
    let modelRoute = opts.modelRoute;
    let agent = opts.agent;
    let model = opts.model;
    let thinkingLevel = opts.thinkingLevel;
    if (!modelRoute && !resuming && !headless && process.stdin.isTTY && process.stdout.isTTY) {
      const choice = await promptForModelRoute();
      modelRoute = choice.route;
      agent ??= choice.defaultAgent;
    }
    recordInitialModelRoute(workspaceDir, modelRoute);
    if (!model && !resuming && !headless && process.stdin.isTTY && process.stdout.isTTY) {
      const choice = await promptForModelSelection({
        route: modelRoute ?? { mode: "gateway", provider: "vercel" },
        agent,
      });
      agent = choice.agent;
      model = choice.model;
      thinkingLevel = choice.thinkingLevel;
    }
    if (!model && !resuming && headless) {
      const profile = parseModelProfile(opts.modelProfile);
      if (!profile && !opts.yes) {
        throw new SetupProtocolError({
          code: "MODEL_SELECTION_REQUIRED",
          message:
            "Choose a model profile for the first headless setup, or pass --yes to accept best.",
          missingInputs: ["model.profile"],
          choices: [
            { value: "best", label: "Best benchmark score", recommended: true },
            { value: "value", label: "Best score within 2.5× relative benchmark cost" },
            { value: "budget", label: "Lowest-cost recommended combination" },
          ],
          actions: [
            {
              id: "select-model-profile",
              description: "Resume with a benchmark-backed model profile.",
              resumeArgs: ["--model-profile", "<choice>"],
            },
            {
              id: "accept-defaults",
              description: "Accept the best profile and deterministic project defaults.",
              resumeArgs: ["--yes"],
            },
          ],
        });
      }
      const choice = await resolveModelProfile({
        profile: profile ?? "best",
        route: modelRoute ?? { mode: "gateway", provider: "vercel" },
        agent,
      });
      agent = choice.agent;
      model = choice.model;
      thinkingLevel = choice.thinkingLevel;
    }
    // Complete interactive project selection before Ink ever takes ownership
    // of the terminal. Besides producing a cleaner onboarding sequence, this
    // avoids transferring stdin between two independent prompt runtimes.
    //
    // A local-subscription route needs no platform link, so skip it rather
    // than prompt for the Vercel login the user just declined. On resume the
    // route comes from the login checkpoint, or from the generated config when
    // setup was interrupted before login; the prompt above is first-run only.
    const linkRoute = modelRoute ?? persistedModelRoute(workspaceDir, registered.id);
    if (
      linkRoute?.mode !== "local" &&
      !headless &&
      process.stdin.isTTY &&
      process.stdout.isTTY &&
      !(await readWorkspaceLink(workspaceDir))
    ) {
      await ensureVercelLink({
        workspaceDir,
        interactive: true,
        env: process.env,
        teamId: opts.teamId,
        projectId: opts.vercelProjectId,
        onLog: (message) => console.log(message),
      });
    }
    const releaseSetupLock = acquireSetupLock(workspaceDir);
    const abortController = new AbortController();
    let reporter: Awaited<ReturnType<typeof createSetupReporter>> | undefined;
    try {
      reporter = await createSetupReporter({
        workspaceDir,
        projectId: registered.id,
        noTui: opts.noTui,
        outputMode,
        onCancel: () => abortController.abort(),
      });
      if (!reporter.interactive && outputMode === "human") {
        console.log(
          `${GREEN}✓${RESET} ${resuming ? "Resuming" : "Created"} ${BOLD}${workspaceDir}${RESET}`,
        );
        console.log(
          `  ${DIM}First project:${RESET} ${BOLD}${registered.id}${RESET} → ${registered.targetRel}\n`,
        );
        if (deepsecDependency.startsWith("file:")) {
          console.log(`  ${DIM}Local package:${RESET} ${deepsecDependency}\n`);
        }
      }
      const result = await runSetupWorkflow({
        workspaceDir,
        projectId: registered.id,
        projectRoot: registered.targetAbs,
        agent,
        model,
        thinkingLevel,
        modelRoute,
        packageManager: opts.packageManager,
        skipInstall: opts.skipInstall,
        nonInteractive: headless,
        teamId: opts.teamId,
        vercelProjectId: opts.vercelProjectId,
        allowProjectCreate: opts.yes,
        vercelProjectName:
          opts.vercelProjectName ?? deterministicVercelProjectName(registered.id, targetAbs),
        concurrency: opts.concurrency,
        through: opts.through,
        maxCostUsd: opts.maxCostUsd,
        maxDurationMs: opts.maxDurationMs,
        signal: abortController.signal,
        reporter,
      });
      await reporter.close("success");
      printSetupSummary(result, {
        workspaceDir,
        projectId: registered.id,
        logPath: reporter.logPath,
        outputMode,
      });
    } catch (error) {
      await reporter?.close(abortController.signal.aborted ? "cancelled" : "error");
      if (reporter?.logPath && outputMode === "human") {
        console.error(`Full setup log: ${reporter.logPath}`);
      }
      throw error;
    } finally {
      releaseSetupLock();
    }
    return;
  }

  console.log(
    `${GREEN}✓${RESET} ${resuming ? "Resuming" : "Created"} ${BOLD}${workspaceDir}${RESET}`,
  );
  console.log(
    `  ${DIM}First project:${RESET} ${BOLD}${registered.id}${RESET} → ${registered.targetRel}\n`,
  );

  console.log("Scaffold-only setup complete. Next:\n");
  if (wsRel !== ".") console.log(`  cd ${wsRel}`);
  console.log(`  pnpm install                          ${DIM}# installs deepsec${RESET}`);
  console.log(
    `  ${DIM}# Set AI_GATEWAY_API_KEY in .env.local (or skip if claude/codex CLI is logged in)${RESET}`,
  );
  console.log();
  console.log(
    `  ${YELLOW}Paste this into your coding agent${RESET} ${DIM}(Claude Code, Cursor, Codex, OpenCode, Pi, etc.):${RESET}`,
  );
  console.log();
  printAgentPrompt(registered.id, registered.targetRel);
  console.log();
  console.log(`  Then run:`);
  console.log(`    pnpm deepsec scan`);
  console.log(`    pnpm deepsec process`);
  console.log();
  console.log(`  ${DIM}# --project-id is auto-resolved while there's only one project.${RESET}`);
  console.log(`  ${DIM}# Register another codebase later: deepsec init-project <root>${RESET}`);
}

function printAgentPrompt(id: string, targetRel: string): void {
  const lines = [
    `Read node_modules/deepsec/SKILL.md to understand the tool. Then`,
    `read data/${id}/SETUP.md and follow it: open ${targetRel}, skim`,
    `its README + AGENTS.md/CLAUDE.md + a handful of representative`,
    `code files, then replace each section of data/${id}/INFO.md.`,
    ``,
    `Keep it SHORT — target 50–100 lines total. Pick 3–5 examples per`,
    `section, not exhaustive enumeration. Name primitives (auth`,
    `helpers, middleware) but no line numbers. Skip generic CWE`,
    `categories — built-in matchers cover those. Cover only what's`,
    `project-specific. INFO.md is injected into every scan batch;`,
    `verbose context dilutes signal.`,
  ];
  for (const l of lines) console.log(`    ${CYAN}${l}${RESET}`);
}

function writeFile(dir: string, name: string, content: string) {
  const p = path.join(dir, name);
  if (fs.existsSync(p)) return;
  fs.writeFileSync(p, content);
}

/**
 * npm rejects package names starting with a dot. `.deepsec` (the default
 * workspace dir) would land that way; sanitize it.
 */
function workspacePackageName(workspaceDir: string): string {
  const base = path.basename(workspaceDir);
  return base.startsWith(".") ? "deepsec-workspace" : base;
}

function packageJson(name: string, deepsecDependency: string): string {
  // Published CLIs pin their exact package version. A bundle launched from a
  // source checkout points at that checkout instead, so one-command local
  // onboarding cannot accidentally install an older npm artifact that happens
  // to carry the same version number.
  return `${JSON.stringify(
    {
      name,
      version: "0.1.0",
      private: true,
      description: "deepsec scanning workspace",
      type: "module",
      // Empty workspaces array marks this package.json as a workspace root
      // for npm and yarn — both walk up looking for a package.json that
      // declares `workspaces`, and stop at the first hit. Without this, a
      // parent monorepo's workspace would absorb `.deepsec/`.
      workspaces: [],
      // Pin the package manager for this workspace. Without this, pnpm
      // walks up looking for a `packageManager` field and adopts whatever
      // it finds in an ancestor — so a parent repo declaring
      // `"packageManager": "yarn@..."` makes `pnpm install` from
      // `.deepsec/` refuse to run. Setting it here stops the walk at the
      // workspace root.
      packageManager: detectPackageManager(),
      dependencies: { deepsec: deepsecDependency },
    },
    null,
    2,
  )}\n`;
}

/**
 * A failed local run may already have installed the registry package before a
 * newer checkout learned to self-reference. Repair only local-checkout runs;
 * published CLIs must preserve intentional user dependency overrides.
 */
function reconcileLocalDeepsecDependency(workspaceDir: string, dependency: string): void {
  if (!dependency.startsWith("file:")) return;
  const pkgPath = path.join(workspaceDir, "package.json");
  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
  if (pkg.dependencies?.deepsec === dependency) return;
  pkg.dependencies = { ...(pkg.dependencies ?? {}), deepsec: dependency };
  fs.writeFileSync(pkgPath, `${JSON.stringify(pkg, null, 2)}\n`);
}

/**
 * Best-effort `packageManager` value for the scaffolded package.json.
 *
 * Tries the running pnpm/npm/yarn version (via `npm_config_user_agent`,
 * which all three set when they spawn child processes). Falls back to a
 * known-stable pnpm version so the resulting package.json is always
 * valid even when init is run from a bare shell. The README / printed
 * Next steps assume pnpm, so we always emit a `pnpm@*` value.
 */
function detectPackageManager(): string {
  const ua = process.env.npm_config_user_agent;
  if (ua) {
    const m = ua.match(/pnpm\/(\d+\.\d+\.\d+)/);
    if (m) return `pnpm@${m[1]}`;
  }
  // Recent pnpm 9 LTS — kept conservative; users with a newer pnpm
  // installed will see a Corepack mismatch warning but installs work.
  return "pnpm@9.15.4";
}

function pnpmWorkspaceYaml(): string {
  // Mirror of the `workspaces: []` in package.json, for pnpm. pnpm reads
  // this file (not package.json:workspaces) — empty `packages` list means
  // ".deepsec/ is its own workspace root with no members beyond itself."
  return `packages: []\n`;
}

/**
 * Empty config with the insert marker. `init-project` (and the same code
 * path called from `init`) appends new project entries above the marker.
 */
function emptyConfigTs(): string {
  return `import { defineConfig } from "deepsec/config";
import { generatedMatchersPlugin } from "./generated-matchers.js";

export default defineConfig({
  projects: [
    ${PROJECTS_INSERT_MARKER}
  ],
  plugins: [generatedMatchersPlugin],
});
`;
}

function generatedMatchersTs(): string {
  return `import { compileDeclarativeMatchers, type DeepsecPlugin } from "deepsec/config";

export const generatedMatchersPlugin: DeepsecPlugin = {
  name: "deepsec-generated-matchers",
  matchers: compileDeclarativeMatchers([]),
};
`;
}

function readmeMd(id: string, targetRel: string): string {
  return `# deepsec

This directory holds the [deepsec](https://www.npmjs.com/package/deepsec)
config for the parent repo. Checked into git so teammates inherit
project context (auth shape, threat model, custom matchers); generated
scan output is gitignored.

Currently configured project: \`${id}\` (target: \`${targetRel}\`).

## Setup

\`npx deepsec init\` created this workspace and normally completes its
install, exact Vercel project link, Sandbox/model probes, threat model,
coverage-guided scans, custom matchers, and first AI processing run.

If setup was interrupted, run \`pnpm deepsec setup\` here or re-run the
original init command. Checkpoints in \`data/${id}/setup/setup-state.json\`
skip completed work. The linked Vercel project is always in Sandbox scope.

Use \`--model-auth direct --ai-provider <provider>
--ai-api-key-env <ENV_NAME>\` to use a user-owned model credential; secret
values remain in the environment or \`.env.local\`. Use \`--model-auth local\`
to rely on a machine-wide \`claude\`/\`codex\` login instead — no API key or
env vars needed.

## Daily commands

\`\`\`bash
pnpm deepsec scan
pnpm deepsec process     --concurrency 5
pnpm deepsec revalidate  --concurrency 5                  # cuts FP rate
pnpm deepsec export      --format md-dir --out ./findings
\`\`\`

\`--project-id\` is auto-resolved while there's only one project in
\`deepsec.config.ts\`. Once you've added a second project, pass
\`--project-id ${id}\` (or whichever id you want) explicitly.

\`scan\` is free (regex only). \`process\` is the AI stage (≈$0.30/file
on Opus by default). Run state goes to \`data/${id}/\`.

## Adding another project

To scan another codebase from this same \`.deepsec/\`:

\`\`\`bash
pnpm deepsec init-project ../some-other-package   # path relative to .deepsec/
\`\`\`

Appends an entry to \`deepsec.config.ts\` and writes
\`data/<id>/{INFO.md,SETUP.md,project.json}\`. Open the new SETUP.md
in your agent to fill in INFO.md.

## Layout

\`\`\`
deepsec.config.ts        Project list (one entry per scanned repo)
data/${id}/
  INFO.md                Repo context — checked into git, hand-curated
  SETUP.md               Agent setup prompt — checked in, deletable
  project.json           Generated (gitignored)
  files/                 One JSON per scanned source file (gitignored)
  runs/                  Run metadata (gitignored)
  reports/               Generated markdown reports (gitignored)
AGENTS.md                Pointer for coding agents
.env.local               Tokens (gitignored)
\`\`\`

## Docs

After \`pnpm install\`:

- Skill: \`node_modules/deepsec/SKILL.md\`
- Full docs: \`node_modules/deepsec/dist/docs/{getting-started,configuration,models,writing-matchers,plugins,architecture,data-layout,vercel-setup,faq}.md\`

Or browse on
[GitHub](https://github.com/vercel/deepsec/tree/main/docs).
`;
}

/**
 * Workspace-level AGENTS.md — generic pointer to per-project SETUP.md
 * files and to the deepsec skill. Per-project setup prompts now live at
 * `data/<id>/SETUP.md` (written by `init-project` / `init`).
 */
function workspaceAgentsMd(): string {
  return `# Agent setup

This is a deepsec scanning workspace. Each registered project has its
own setup prompt at \`data/<id>/SETUP.md\` — open the relevant one when
asked to set a project up.

## Common tasks

- **Set up or resume a project**: run \`pnpm deepsec setup\`. For a
  scaffold-only/manual setup, read \`data/<id>/SETUP.md\` and follow it.
- **Add a new project**: run \`deepsec init-project <root>\` — it
  scaffolds \`data/<id>/\` and prints/writes the setup prompt for the
  new project.
- **Write a custom matcher** (only after a real true-positive shows you
  a pattern worth keeping): read
  \`node_modules/deepsec/dist/docs/writing-matchers.md\`.

## Reference

The deepsec skill is at \`node_modules/deepsec/SKILL.md\` (after
\`pnpm install\`). The full docs ship at
\`node_modules/deepsec/dist/docs/\`.
`;
}

function gitignore(): string {
  // Keep curated files (INFO.md, SETUP.md) tracked so teammates inherit
  // project context. Ignore the regenerable / heavy / sensitive bits.
  return `node_modules/
.env*.local
.vercel/
.deepsec-setup.lock

# Scan output — regenerated by \`deepsec scan\` / \`process\`. INFO.md
# and SETUP.md (manually edited) stay tracked.
data/*/files/
data/*/runs/
data/*/reports/
data/*/project.json
data/*/setup/
`;
}

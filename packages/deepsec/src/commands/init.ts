import fs from "node:fs";
import path from "node:path";
import { BOLD, DIM, GREEN, RESET, YELLOW } from "../formatters.js";
import { requireExistingDir } from "../require-dir.js";
import { PROJECTS_INSERT_MARKER, registerProject } from "./init-project.js";

const IGNORED_WORKSPACE_ENTRIES = new Set([".git", ".DS_Store"]);

interface InitOpts {
  workspace?: string;
  targetRoot?: string;
  id?: string;
  force?: boolean;
}

export function initCommand(opts: InitOpts) {
  // Defaults: scaffold `.deepsec/` inside the current codebase, with the
  // codebase itself as the first project. Override either by passing
  // explicit positional args.
  const workspaceArg = opts.workspace ?? ".deepsec";
  const targetArg = opts.targetRoot ?? ".";

  const workspaceDir = path.resolve(process.cwd(), workspaceArg);
  let targetAbs: string;
  try {
    targetAbs = requireExistingDir(targetArg, "<target-root>");
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  }

  if (fs.existsSync(workspaceDir)) {
    const meaningful = fs
      .readdirSync(workspaceDir)
      .filter((e) => !IGNORED_WORKSPACE_ENTRIES.has(e));
    if (meaningful.length > 0 && !opts.force) {
      console.error(
        `Workspace directory is not empty: ${workspaceDir}\n` +
          `Use --force to write into a non-empty directory.`,
      );
      process.exit(1);
    }
  }

  // Workspace skeleton: empty config (with marker), README, AGENTS, env.
  fs.mkdirSync(workspaceDir, { recursive: true });
  writeFile(workspaceDir, "package.json", packageJson(workspacePackageName(workspaceDir)));
  // Sever .deepsec/ from any ancestor monorepo. npm and yarn walk up looking
  // for a `package.json` with `workspaces` defined; pnpm walks up looking
  // for a `pnpm-workspace.yaml`. Both stop at the first hit, so dropping a
  // pnpm-workspace.yaml here (and an empty `workspaces: []` in package.json,
  // see packageJson()) makes `.deepsec/` its own root regardless of what
  // the parent repo defines. Lets `npm/yarn/pnpm install` from `.deepsec/`
  // manage only this directory's deps.
  writeFile(workspaceDir, "pnpm-workspace.yaml", pnpmWorkspaceYaml());
  writeFile(workspaceDir, "deepsec.config.ts", emptyConfigTs());
  writeFile(workspaceDir, "AGENTS.md", workspaceAgentsMd());
  writeFile(workspaceDir, ".env.local", envLocal());
  writeFile(workspaceDir, ".gitignore", gitignore());

  // Register the first project via the shared code path. Same writes
  // `init-project` would do: data/<id>/{project.json,INFO.md,SETUP.md}
  // and append to projects[].
  let registered: ReturnType<typeof registerProject>;
  try {
    registered = registerProject({
      workspaceDir,
      targetRoot: targetAbs,
      id: opts.id,
      force: opts.force,
    });
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  }

  // README references the project, so write it AFTER registration.
  writeFile(workspaceDir, "README.md", readmeMd(registered.id, registered.targetRel));

  const wsRel = path.relative(process.cwd(), workspaceDir) || ".";
  console.log(`${GREEN}✓${RESET} Created ${BOLD}${workspaceDir}${RESET}`);
  console.log(
    `  ${DIM}First project:${RESET} ${BOLD}${registered.id}${RESET} → ${registered.targetRel}\n`,
  );
  console.log("Next:\n");
  if (wsRel !== ".") console.log(`  cd ${wsRel}`);
  console.log(`  pnpm install                          ${DIM}# installs deepsec${RESET}`);
  console.log(`  ${DIM}# Set AI_GATEWAY_API_KEY in .env.local${RESET}`);
  console.log();
  console.log(
    `  ${YELLOW}Paste this into your coding agent${RESET} ${DIM}(Claude Code, Cursor, Codex CLI):${RESET}`,
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
  for (const l of lines) console.log(`    ${BOLD}>${RESET} ${l}`);
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

function packageJson(name: string): string {
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
      dependencies: { deepsec: "^0.1.0" },
    },
    null,
    2,
  )}\n`;
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

export default defineConfig({
  projects: [
    ${PROJECTS_INSERT_MARKER}
  ],
});
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

1. \`pnpm install\` — installs deepsec.
2. Add your AI Gateway token to \`.env.local\`. See
   \`node_modules/deepsec/dist/docs/vercel-setup.md\` after install.
3. Open the parent repo in your coding agent (Claude Code, Cursor, …)
   and have it follow \`data/${id}/SETUP.md\` to fill in
   \`data/${id}/INFO.md\`.

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

- **Set up a project for scanning**: read \`data/<id>/SETUP.md\` and
  follow it (read \`node_modules/deepsec/SKILL.md\`, then fill
  \`data/<id>/INFO.md\` from the target codebase).
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

function envLocal(): string {
  // One-line gateway setup. deepsec expands AI_GATEWAY_API_KEY at startup
  // into ANTHROPIC_AUTH_TOKEN / OPENAI_API_KEY / *_BASE_URL, so a user
  // who only has a gateway key is fully wired with this single line.
  return `AI_GATEWAY_API_KEY=
`;
}

function gitignore(): string {
  // Keep curated files (INFO.md, SETUP.md) tracked so teammates inherit
  // project context. Ignore the regenerable / heavy / sensitive bits.
  return `node_modules/
.env*.local

# Scan output — regenerated by \`deepsec scan\` / \`process\`. INFO.md
# and SETUP.md (manually edited) stay tracked.
data/*/files/
data/*/runs/
data/*/reports/
data/*/project.json
`;
}

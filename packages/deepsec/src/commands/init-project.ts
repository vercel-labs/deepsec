import fs from "node:fs";
import path from "node:path";
import { dataDir, ensureProject } from "@deepsec/core";
import { BOLD, DIM, GREEN, RESET, YELLOW } from "../formatters.js";
import { requireExistingDir } from "../require-dir.js";
import { validateProjectId } from "../resolve-project-id.js";

export const PROJECTS_INSERT_MARKER = "// <deepsec:projects-insert-above>";

const CONFIG_FILENAMES = [
  "deepsec.config.ts",
  "deepsec.config.mjs",
  "deepsec.config.js",
  "deepsec.config.cjs",
];

/** Walk up from `start` looking for a deepsec config file. */
function findWorkspaceRoot(start: string): string | undefined {
  let dir = path.resolve(start);
  while (true) {
    for (const name of CONFIG_FILENAMES) {
      if (fs.existsSync(path.join(dir, name))) return dir;
    }
    const parent = path.dirname(dir);
    if (parent === dir) return undefined;
    dir = parent;
  }
}

interface RegisterResult {
  id: string;
  targetRel: string;
  targetAbs: string;
  configPath: string;
  setupMdPath: string;
  infoMdPath: string;
}

/**
 * Register a project in an existing deepsec workspace. Shared by `init`
 * (called once for the first project, after the workspace skeleton is in
 * place) and `init-project` (called against an existing workspace).
 *
 * Writes:
 *   - data/<id>/project.json (via ensureProject — also auto-detects githubUrl)
 *   - data/<id>/INFO.md (placeholder template)
 *   - data/<id>/SETUP.md (per-project agent setup prompt)
 *   - appends `{ id, root }` to projects[] in deepsec.config.ts
 */
export function registerProject(opts: {
  workspaceDir: string;
  targetRoot: string;
  id?: string;
  force?: boolean;
}): RegisterResult {
  const workspaceDir = fs.realpathSync(path.resolve(opts.workspaceDir));
  const targetAbs = requireExistingDir(opts.targetRoot, "<target-root>");
  const id = validateProjectId(opts.id ?? path.basename(targetAbs));
  const targetRel = path.relative(workspaceDir, targetAbs);

  const configPath = findConfigInWorkspace(workspaceDir);
  if (!configPath) {
    throw new Error(
      `Could not find deepsec.config.ts in ${workspaceDir}.\n` +
        `  init-project must run inside a workspace created by \`deepsec init\`.`,
    );
  }

  const projectDataDir = path.join(workspaceDir, dataDir(id));
  const dataExists = fs.existsSync(projectDataDir) && fs.readdirSync(projectDataDir).length > 0;
  const inConfig = configIncludesProjectId(configPath, id);
  if ((dataExists || inConfig) && !opts.force) {
    throw new Error(
      `Project "${id}" already exists in this workspace ` +
        `(${dataExists ? "data dir" : "config"} occupied).\n` +
        `  Pass --force to overwrite, or pick a different --id.`,
    );
  }

  // Run all writes from the workspace root so DEEPSEC_DATA_ROOT-relative
  // paths via `dataDir(id)` land correctly. Restore on exit.
  const originalCwd = process.cwd();
  try {
    process.chdir(workspaceDir);
    ensureProject(id, targetAbs);
    const projectDir = dataDir(id);
    fs.mkdirSync(projectDir, { recursive: true });
    const infoMdPath = path.join(projectDir, "INFO.md");
    if (!fs.existsSync(infoMdPath) || opts.force) {
      fs.writeFileSync(infoMdPath, infoMdTemplate(id));
    }
    const setupMdPath = path.join(projectDir, "SETUP.md");
    fs.writeFileSync(setupMdPath, setupMdTemplate(id, targetRel));

    insertProjectIntoConfig(configPath, id, targetRel);

    return {
      id,
      targetRel,
      targetAbs,
      configPath,
      setupMdPath: path.resolve(setupMdPath),
      infoMdPath: path.resolve(infoMdPath),
    };
  } finally {
    process.chdir(originalCwd);
  }
}

function findConfigInWorkspace(workspaceDir: string): string | undefined {
  for (const name of CONFIG_FILENAMES) {
    const p = path.join(workspaceDir, name);
    if (fs.existsSync(p)) return p;
  }
  return undefined;
}

function configIncludesProjectId(configPath: string, id: string): boolean {
  const src = fs.readFileSync(configPath, "utf-8");
  const re = new RegExp(`id:\\s*["'\`]${escapeRegex(id)}["'\`]`);
  return re.test(src);
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function insertProjectIntoConfig(configPath: string, id: string, root: string): void {
  const src = fs.readFileSync(configPath, "utf-8");
  if (!src.includes(PROJECTS_INSERT_MARKER)) {
    throw new Error(
      `Marker "${PROJECTS_INSERT_MARKER}" not found in ${configPath}.\n` +
        `  init-project relies on this marker to know where to add the new project.\n` +
        `  Either add it back inside the projects[] array, or add the project entry by hand:\n` +
        `    { id: "${id}", root: ${JSON.stringify(root)} },`,
    );
  }
  // Preserve the marker's leading indent on the inserted line so the
  // appended entry sits at the same indent level.
  const replacer = (match: string) => {
    const m = match.match(/^([\t ]*)(.*)$/m);
    const indent = m?.[1] ?? "    ";
    return `${indent}{ id: ${JSON.stringify(id)}, root: ${JSON.stringify(root)} },\n${match}`;
  };
  const re = new RegExp(`^[\\t ]*${escapeRegex(PROJECTS_INSERT_MARKER)}.*$`, "m");
  const updated = src.replace(re, replacer);
  fs.writeFileSync(configPath, updated);
}

function infoMdTemplate(id: string): string {
  return `# ${id}

> Replace each section. Target 50–100 lines total. INFO.md is injected
> into every AI scan batch — verbose context dilutes signal.
> See \`SETUP.md\` for the rubric + a coding-agent prompt.

## What this codebase does

<one paragraph: what the app does, what stack, what users it serves>

## Auth shape

<the 3–5 most important auth primitives BY NAME. The scanner doesn't
need every helper — just enough to recognize when one is missing>

## Threat model

<2–4 sentences: what an attacker would want, ranked by impact.
Skip generic security boilerplate>

## Project-specific patterns to flag

<3–5 patterns unique to THIS codebase, one example each. Avoid
generic CWE categories — built-in matchers cover those>

## Known false-positives

<3–5 paths/patterns that look risky but are intentional —
fork-specific stubs, dev fixtures, intended-public endpoints>
`;
}

function setupMdTemplate(id: string, targetRel: string): string {
  return `# Agent setup for \`${id}\`

This is a deepsec scanning workspace. Project \`${id}\` was just registered
(target: \`${targetRel}\`). Setup is incomplete — \`data/${id}/INFO.md\`
still has placeholder sections.

## What to do

1. **Read the deepsec skill.** After \`pnpm install\`, the file is at
   \`node_modules/deepsec/SKILL.md\`. It maps every doc topic to a file
   under \`node_modules/deepsec/dist/docs/\`. Read \`getting-started.md\`,
   \`configuration.md\`, and \`writing-matchers.md\` (skim the rest).

2. **Fill in \`data/${id}/INFO.md\`.** It's auto-injected into the AI
   prompt for every batch — keep it short and selective.

   **Length budget: 50–100 lines total.** Verbose context dilutes
   signal in the scanner's prompt window. The goal is "what would a
   reviewer miss if they didn't read this?", not exhaustive enumeration.

   **Per-section rubric**:
   - Pick 3–5 representative items per section. **Don't list every
     file, helper, or callsite** — pick the patterns.
   - Name primitives by their public name (e.g. \`withAuthentication\`,
     \`auth.can()\`, \`isTeamAdmin\`). **No line numbers.** Don't enumerate
     more than 5 paths in any list.
   - Skip generic CWE categories — built-in matchers already cover
     "SSRF", "SQL injection", "XSS". Cover what's *project-specific*:
     internal auth helpers, custom middleware names, fork-specific
     stubs, intended-public endpoints.
   - One short paragraph or 3–5 short bullets per section. Not both.

   Source material (read in this order, stop when you have enough):
   - \`${targetRel}/README.md\`
   - any \`AGENTS.md\` / \`CLAUDE.md\` in \`${targetRel}\`
   - \`${targetRel}/package.json\` (or \`go.mod\`, \`pyproject.toml\`, etc.)
   - 5–10 representative code files (entry points, auth helpers) — not
     a full code tour.

3. **(Optional) Add custom matchers** for repo-specific patterns the
   built-in matchers won't catch. Read
   \`node_modules/deepsec/dist/docs/writing-matchers.md\` first; the
   workflow there starts from a confirmed finding and grows the matcher
   from it. Don't add matchers speculatively — wait for a real TP.

## When you're done

The user will run:

\`\`\`bash
pnpm deepsec scan    --project-id ${id}
pnpm deepsec process --project-id ${id}
\`\`\`

You can delete this file once setup is complete.
`;
}

/* CLI entry point — commander enforces <target-root> presence via the
   command spec, so we don't re-validate it here. */
export function initProjectCommand(opts: {
  targetRoot?: string;
  id?: string;
  force?: boolean;
}): void {
  const workspaceDir = findWorkspaceRoot(process.cwd());
  if (!workspaceDir) {
    console.error(
      `No .deepsec/ workspace found in or above ${process.cwd()}.\n` +
        `  Run \`deepsec init\` from your repo root first, then cd into .deepsec/\n` +
        `  before adding more projects.`,
    );
    process.exit(1);
  }
  if (!opts.targetRoot) {
    // Defensive: commander should have caught this. Keeps the type checker happy.
    process.exit(1);
  }

  let result: RegisterResult;
  try {
    result = registerProject({
      workspaceDir,
      targetRoot: opts.targetRoot,
      id: opts.id,
      force: opts.force,
    });
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  }

  console.log(
    `${GREEN}✓${RESET} Added project ${BOLD}${result.id}${RESET} → ${result.targetRel}\n`,
  );
  console.log(
    `  ${YELLOW}Paste this into your coding agent${RESET} ${DIM}(Claude Code, Cursor, Codex, OpenCode, Pi, etc.):${RESET}`,
  );
  console.log();
  printAgentPrompt(result.id, result.targetRel);
  console.log();
  console.log(`  Then run: ${DIM}pnpm deepsec scan --project-id ${result.id}${RESET}`);
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

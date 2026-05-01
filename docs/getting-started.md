# Getting started

## Install

Requires **Node.js 22+**. The recipe below uses pnpm; npm and yarn
work the same way.

deepsec lives in a `.deepsec/` directory at the root of your codebase
— checked into the same git repo, so config, project context, and
custom matchers travel with the code. Generated scan output (findings,
runs, reports) stays gitignored.

From the root of the codebase you want to scan:

```bash
npx deepsec init                                   # creates .deepsec/ + registers this repo
cd .deepsec
pnpm install                                       # installs deepsec
```

`init` lays down a minimal scaffold inside `.deepsec/`: `package.json`,
`deepsec.config.ts` (one `projects[]` entry pointing at `..`, id
derived from your repo dir's basename), `data/<id>/INFO.md` (template
with section placeholders), `data/<id>/SETUP.md` (per-project agent
prompt), workspace-level `AGENTS.md`, `.env.local`, `.gitignore`. No
custom matchers in the scaffold — add those later, only when a real
finding shapes one for you.

Open `.env.local` and fill in `ANTHROPIC_AUTH_TOKEN`. Get one from
[Vercel AI Gateway](https://vercel.com/ai-gateway) (one token covers
Claude and Codex) or set `ANTHROPIC_BASE_URL=https://api.anthropic.com`
to use Anthropic directly. See [vercel-setup.md](vercel-setup.md).

To scan a *different* codebase from the same `.deepsec/`, run
`pnpm deepsec init-project <path>` — relative paths resolve against
`.deepsec/`'s parent.

## Fill in INFO.md

`INFO.md` is what makes deepsec project-aware. It's injected into the
AI prompt for every batch — vague content here means vague findings.

### Option A: let your coding agent do it (recommended)

Open the *parent repo* (the codebase you scanned, not `.deepsec/`) in
your coding agent (Claude Code, Codex, Cursor, …) and paste the prompt
that `deepsec init` printed. It walks the agent through:

1. Read `.deepsec/node_modules/deepsec/SKILL.md` to understand the tool.
2. Open `.deepsec/data/<id>/SETUP.md` for project-specific instructions.
3. Skim the codebase, then replace each section of
   `.deepsec/data/<id>/INFO.md`.

The same prompt is shown in the project root README and is what `init`
prints to stdout after scaffold.

### Option B: by hand

The processor auto-loads `data/<id>/INFO.md` from the workspace's data
dir. Edit it directly — no extra wiring needed in
`deepsec.config.ts`. INFO.md is optional but worth keeping; even a
paragraph noticeably improves the AI's output.

## Run a scan

Before the first command: deepsec writes per-project state to
`./data/<project-id>/` next to your config — `files/` (one JSON per
scanned source file), `runs/`, plus `project.json` and the optional
`INFO.md` / `config.json`. The directory is gitignored by default; see
[data-layout.md](data-layout.md) for the full schema.

```bash
pnpm deepsec scan
```

`--project-id` is auto-resolved when the config has a single project
(the common case). Pass `--project-id <id>` once you've registered
more than one project. Pass `--root <path>` to override the resolved
path — useful for one-off scans against a different checkout.

`scan` runs ~110 regex matchers across the codebase. There are no AI calls at this stage. 
On a 2,000-file project it takes ~15s. Output goes to
`data/<id>/files/` as one JSON file per scanned source file (called a
`FileRecord`).

```bash
pnpm deepsec status
```

shows the current state: how many files were scanned, how many are
pending AI investigation, etc.

## Run the AI investigation

```bash
pnpm deepsec process --concurrency 5
```

Defaults: Claude Opus, 5 files per batch,
5 batches in parallel = 25 files in flight at once. You can lower the
parallelism (`--concurrency 1`) or set `--limit 50` to budget-cap.

A rough cost guide (Opus, default settings):

| Files | Approx cost | Approx wall time |
|---|---|---|
| 100 | $25–60 | 5–15 min |
| 500 | $130–300 | 25–60 min |
| 2,000 | $500–1200 | 1.5–4 hr |

Costs swing 2–3x based on file complexity. Run `--limit 50` first to
calibrate before committing to the full pass.

For a cheaper backend:

```bash
pnpm deepsec process --agent codex --model gpt-5.5
```

Codex is the OpenAI-flavored backend. Same prompt, same JSON output,
different agent loop. Try both on a small sample to see which catches
shapes you care about. See [models.md](models.md) for the full
backend / model matrix, refusal handling, and how to swap in newer
models.

## Triage and revalidate

```bash
pnpm deepsec triage --severity HIGH
pnpm deepsec revalidate --min-severity HIGH
```

- **triage**: classifies findings P0/P1/P2 without re-reading the code.
  ~1¢/finding.
- **revalidate**: re-reads the code and the git history, then emits a
  TP/FP/Fixed/Uncertain verdict. Comparable cost to `process`. Cuts FP
  rate by 50%+ on most repos.

Both optional, but worth running on the HIGH/CRITICAL set.

## Get the findings out

```bash
pnpm deepsec export --format md-dir --out ./findings
pnpm deepsec export --format json   --out findings.json
```

`md-dir` writes one markdown file per finding under
`./findings/{CRITICAL,HIGH,MEDIUM,…}/`. `json` writes a single array
suitable for piping to a downstream issue tracker.

For a quick aggregate look:

```bash
pnpm deepsec metrics
```

(Each of these commands accepts `--project-id <id>` if your config has
multiple projects; the auto-resolution only kicks in when there's
exactly one.)

## Next

- [docs/writing-matchers.md](writing-matchers.md) — when a TP finding
  isn't covered by an existing matcher, prompt your coding agent to
  write one for the pattern.
- [docs/configuration.md](configuration.md) — every field on
  `deepsec.config.ts` and `data/<id>/config.json`.
- [docs/models.md](models.md) — defaults, `--agent` / `--model`,
  refusal handling, future models.
- [docs/plugins.md](plugins.md) — for org-specific patterns that don't
  belong in the public matcher set.

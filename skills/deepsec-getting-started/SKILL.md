---
name: deepsec-getting-started
description: First-scan walkthrough for deepsec — install, register the project, write INFO.md, run scan + process + revalidate, export findings. Activates when the user is setting up deepsec for the first time or running their first scan.
---

# Getting started with deepsec

deepsec is an AI-powered vulnerability scanner. It lives in a
`.deepsec/` directory at the root of the repo you want to scan,
checked into git so teammates inherit project context. Generated scan
output (findings, runs, reports) stays gitignored.

## Install

Requires **Node.js 22+**. From the root of the codebase you want to scan:

```bash
npx deepsec init                                   # creates .deepsec/ + registers this repo
cd .deepsec
pnpm install                                       # installs deepsec
```

`init` lays down a minimal scaffold inside `.deepsec/`:
- `package.json` and `pnpm-workspace.yaml` (isolates this dir from any parent monorepo)
- `deepsec.config.ts` (one `projects[]` entry pointing at `..`, id derived from your repo dir's basename)
- `data/<id>/INFO.md` (template with section placeholders)
- `data/<id>/SETUP.md` (per-project agent prompt)
- workspace-level `AGENTS.md`, `.env.local`, `.gitignore`

No custom matchers in the scaffold — add those later, only when a real
finding shapes one for you.

## Pick a credential

Open `.env.local` and pick one of:

- **AI Gateway API key** — set `AI_GATEWAY_API_KEY=vck_…`. Get a key
  from [Vercel AI Gateway](https://vercel.com/ai-gateway). One key
  covers both Claude and Codex.
- **Vercel OIDC token** — run `npx vercel link && npx vercel env pull`
  in this workspace. That writes `VERCEL_OIDC_TOKEN` to `.env.local`,
  which deepsec uses as the gateway credential automatically. Token
  expires after 12 hours; re-pull when you hit auth errors.

Prefer Anthropic directly? Set `ANTHROPIC_AUTH_TOKEN=sk-ant-…` and
`ANTHROPIC_BASE_URL=https://api.anthropic.com` instead. If `claude` or
`codex` is already logged in on this machine, non-sandbox runs
(`process` / `revalidate` / `triage`) skip the token and reuse the
subscription.

For full credential setup, see the `deepsec-sandbox-setup` skill.

## Add another codebase (optional)

To scan a different codebase from the same `.deepsec/`:

```bash
pnpm deepsec init-project <path>     # relative paths resolve against .deepsec/'s parent
```

## Fill in INFO.md

`INFO.md` is what makes deepsec project-aware. It's injected into the
AI prompt for every batch — vague content here means vague findings.

### Option A: let your coding agent do it (recommended)

Open the **parent repo** (the codebase you scanned, not `.deepsec/`) in
your coding agent (Claude Code, Codex, Cursor, …) and paste the prompt
that `deepsec init` printed. It walks the agent through:

1. Read `.deepsec/node_modules/deepsec/SKILL.md` to understand the tool.
2. Open `.deepsec/data/<id>/SETUP.md` for project-specific instructions.
3. Skim the codebase, then replace each section of
   `.deepsec/data/<id>/INFO.md`.

Keep INFO.md SHORT — target 50–100 lines total. Pick 3–5 examples per
section, not exhaustive enumeration. Name primitives (auth helpers,
middleware) but no line numbers. Skip generic CWE categories — built-in
matchers cover those. Cover only what's project-specific.

### Option B: by hand

Edit `data/<id>/INFO.md` directly — no extra wiring needed in
`deepsec.config.ts`. Even a paragraph noticeably improves AI output.

## Run a scan

```bash
pnpm deepsec scan
```

`--project-id` is auto-resolved when the config has a single project
(the common case). Pass `--project-id <id>` once you've registered
more than one project. Pass `--root <path>` to override the resolved
path — useful for one-off scans against a different checkout.

`scan` runs ~110 regex matchers across the codebase. **No AI calls at
this stage.** On a 2,000-file project it takes ~15s. Output goes to
`data/<id>/files/` as one JSON file per scanned source file (called a
`FileRecord`).

```bash
pnpm deepsec status
```

shows the current state: how many files were scanned, how many are
pending AI investigation.

## Run the AI investigation

```bash
pnpm deepsec process --limit 50      # CALIBRATE FIRST
```

**Always run `--limit 50` first** before a full pass. Costs swing 2–3x
based on file complexity; calibrate before committing.

```bash
pnpm deepsec process --concurrency 5
```

Defaults: Codex (gpt-5.5) by default; Claude Opus available via
`--agent claude`. 5 files per batch, 5 batches in parallel = 25 files in
flight at once.

| Files | Approx cost | Approx wall time |
|---|---|---|
| 100   | $25–60     | 5–15 min |
| 500   | $130–300   | 25–60 min |
| 2,000 | $500–1200  | 1.5–4 hr |

Lower parallelism (`--concurrency 1`) or set `--limit 50` to budget-cap.

### If a run errors out

`process` is safe to re-run. If a batch fails (network blip, transient
model error, quota exhausted, you hit Ctrl-C), just run the same command
again — deepsec resumes, skipping files that already finished and
re-investigating only the ones that didn't. Nothing to clean up. Same
applies to `revalidate`.

For a different backend or model:

```bash
pnpm deepsec process --agent claude --model claude-opus-4-7
pnpm deepsec process --agent codex --model gpt-5.5
```

See the `deepsec-models` skill for the full backend / model matrix and
refusal handling.

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
pnpm deepsec metrics                  # quick aggregate
```

`md-dir` writes one markdown file per finding under
`./findings/{CRITICAL,HIGH,MEDIUM,…}/`. `json` writes a single array
suitable for piping to a downstream issue tracker.

Each command accepts `--project-id <id>` if your config has multiple
projects; auto-resolution only kicks in when there's exactly one.

## Where to go next

- **Add custom matchers** for entry-point shapes the defaults miss → `deepsec-writing-matchers`.
- **Configure projects, plugins, matcher filtering** → `deepsec-configuration`.
- **Pick agent / model / handle refusals** → `deepsec-models`.
- **CI / PR review** → `deepsec-pr-review`.

## Hard rules

- Always run `--limit 50` before a full `process` pass on a fresh project.
- Don't commit `data/*/files/` or `data/*/runs/` — gitignored on purpose.
- A blank INFO.md hurts precision; fill it before the first real
  `process` pass.

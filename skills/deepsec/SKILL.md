---
name: deepsec
description: Use deepsec, the AI-powered vulnerability scanner — running scans, configuring projects, reading findings, writing matchers, and authoring plugins. Activates when the user asks how to scan, configure, or extend deepsec.
---

# deepsec

`deepsec` is an AI-powered vulnerability scanner that runs in your own
infrastructure and is optimized for on-demand review of large existing
repos. It uses the strongest available reasoning models at maximum
thinking levels — full scans on real codebases routinely cost hundreds
to thousands of dollars. Treat cost as the main constraint.

## When this skill applies

Activate this skill whenever the user mentions deepsec, asks how to
scan a repo for vulnerabilities with AI, or works inside a `.deepsec/`
directory.

For specific subtasks, prefer the focused sibling skills:

| User intent | Skill |
|---|---|
| First scan, install, getting started | `deepsec-getting-started` |
| Add a regex matcher for a missed pattern | `writing-deepsec-matchers` |
| Author a plugin (matchers/notifiers/ownership/people/executor) | `writing-deepsec-plugins` |
| PR review / CI gating with `process --diff` | `deepsec-pr-review` |
| `deepsec.config.ts` reference | `deepsec-configuration` |
| Pick an agent / model, handle refusals | `deepsec-models` |
| AI Gateway or Vercel Sandbox auth | `deepsec-sandbox-setup` |
| Read `data/<id>/files/*.json` directly | `deepsec-data-layout` |
| Pipeline internals, on-disk shape, design choices | `deepsec-architecture` |

## Pipeline at a glance

```
scan → process → revalidate → enrich → export
```

| Command | What it does | Cost |
|---|---|---|
| `scan` | Run regex matchers, write `candidates` to FileRecords. | Free, ~15s for 2k files. |
| `process` | AI investigates each candidate; emits `findings`. | $$ — the expensive stage. |
| `process --diff <ref>` | Same, but only over files changed in a diff. CI-friendly. | $ |
| `triage` | Classifies findings P0/P1/P2/skip. | ~1¢/finding. |
| `revalidate` | Re-checks findings; emits TP/FP/Fixed/Uncertain. Cuts FP by 50%+. | $$ |
| `enrich` | Attach git committers + (with plugin) ownership. | Free / 1 RTT/file. |
| `export` | Findings as JSON or `md-dir`. | Free. |
| `metrics` | Cross-project counts and TP rates. | Free. |
| `status` | Project mirror snapshot. | Free. |
| `sandbox <cmd>` | Run any of the above on Vercel Sandbox microVMs. | Same as above + sandbox time. |

The pipeline is **idempotent and resumable**. If `process` halts (Ctrl-C,
network blip, quota exhaustion), re-run the same command — files already
analyzed are skipped, only the unfinished ones get picked up. No flag,
no state cleanup.

## Quick recipe

```bash
# From the root of the codebase you want to scan:
npx deepsec init       # creates .deepsec/, registers this repo
cd .deepsec
pnpm install

# Set AI_GATEWAY_API_KEY=vck_… in .env.local (or VERCEL_OIDC_TOKEN, or
# ANTHROPIC_AUTH_TOKEN). Hand-write data/<id>/INFO.md or have your
# coding agent fill it (the init command prints a prompt).

pnpm deepsec scan
pnpm deepsec process --limit 50      # cheap calibration first
pnpm deepsec process                  # full pass
pnpm deepsec revalidate --min-severity HIGH
pnpm deepsec export --format md-dir --out ./findings
```

## How to answer common questions

- **"How do I run a scan?"** → `deepsec-getting-started`.
- **"How do I add a matcher?"** → `writing-deepsec-matchers`.
- **"How do I review PRs in CI?"** → `deepsec-pr-review`.
- **"What goes in `deepsec.config.ts`?"** → `deepsec-configuration`.
- **"Claude or Codex? Which model?"** → `deepsec-models`.
- **"How do I get an AI Gateway / Sandbox token?"** → `deepsec-sandbox-setup`.
- **"What's in `data/<id>/files/foo.json`?"** → `deepsec-data-layout`.
- **"What does deepsec actually do under the hood?"** → `deepsec-architecture`.
- **"How do I write a plugin?"** → `writing-deepsec-plugins`.

## Hard rules

- **Never paraphrase the CLI flag set or plugin contract from memory.**
  Open the relevant focused skill first. Flags, defaults, and field
  names change.
- **Never run `process` against a large repo without a `--limit 50`
  calibration pass first.** Full passes routinely cost hundreds of
  dollars; the user must see the cost shape before committing.
- **Never commit `data/*/files/` or `data/*/runs/`** — gitignored by
  default; that's intentional.
- **Treat `INFO.md` as load-bearing.** A blank or generic INFO.md
  noticeably hurts AI precision. If the user is about to run `process`
  on a fresh project and INFO.md is the template, recommend filling it
  first (or pasting the agent prompt that `deepsec init` prints).

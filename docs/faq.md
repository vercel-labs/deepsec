---
title: "FAQ"
description: "Installation, credentials, costs, CI, state handling, and common operating questions."
---

## How should I install deepsec?

deepsec lives in a `.deepsec/` directory at the root of the repo you
want to scan, checked into git so teammates inherit project context.
From the codebase's repo root:

```bash
npx deepsec init
```

This installs the isolated workspace, links and verifies Vercel Sandbox,
creates the project threat model, checks scan coverage, generates safe
project-specific matchers when needed, and processes candidates. Re-run it
to resume, or use `pnpm deepsec setup` from inside `.deepsec/`.

Use `npx deepsec init --scaffold-only` if you only want the files,
`--model-auth direct` with `--ai-api-key-env` to use your own model key,
or `--model-auth local` to rely on machine-wide `claude`/`codex` logins
without any API key. See
[getting-started](getting-started.md) for details on both.

`.deepsec/` has its own `package.json` and `node_modules/` — separate
from the parent repo's lockfile and tooling. The parent repo only
needs to know `.deepsec/` exists.

To scan another codebase from the same `.deepsec/`, run
`pnpm deepsec init-project <path>`. Each project gets its own
`data/<id>/` subdirectory.

### What about non-JS codebases?

deepsec is polyglot (TS, Go, Python, Lua, Terraform, …). The parent
repo doesn't need to be a Node project — `.deepsec/` is self-contained
and only needs pnpm or npm inside that one directory.

### `.gitignore` policy

The scaffold keeps `INFO.md`, `SETUP.md`, `deepsec.config.ts`, and
`generated-matchers.ts` trackable. It ignores credentials/project-link files
and reproducible state (`.env.local`, `.vercel/`, `data/*/setup/`,
`data/*/files/`, `data/*/runs/`, and reports).

## How much does it cost?

The expensive stage is `process`. When explicitly using Claude Opus with
typical settings
(`--concurrency 5 --batch-size 5`):

| Files | Approx cost | Approx wall time |
|---|---|---|
| 100 | $25–60 | 5–15 min |
| 500 | $130–300 | 25–60 min |
| 2,000 | $500–1200 | 1.5–4 hr |

Costs swing 2–3x based on file complexity. Run `--limit 50` first to
calibrate before committing to a full pass.

`triage` is ~1¢/finding. `revalidate` is comparable to `process`.

## Should I use Claude or Codex?

Both work. Different strengths:

- **Codex (gpt-5.5):** the default; read-only/no-network repository tools
  and strong grep-heavy investigation.
- **Claude (Opus):** strong at authorization shapes and cross-file flows;
  typically more expensive.

Mix them. Run Claude first, then re-process unconvincing findings with
`--agent codex --reinvestigate` for a second opinion. Findings dedupe
across agents.

## Should I use Gateway or my own provider key?

Either works. The project link is always created because it also authorizes
Sandbox; the model route is independent. Gateway is the default and uses
linked-project OIDC. A direct route names your own OpenAI/Anthropic variable,
and a custom Pi route can declare an HTTPS endpoint and auth header.

```bash
MY_ANTHROPIC_KEY=... npx deepsec init \
  --agent claude --model-auth direct \
  --ai-provider anthropic --ai-api-key-env MY_ANTHROPIC_KEY
```

See [vercel-setup](vercel-setup.md) for route persistence, headless
project credentials, and host-side Sandbox credential brokering.

## How accurate is it? What's the FP rate?

After revalidation: ~10–29% on `HIGH+`.

Two things help most:

1. **Revalidate `HIGH+` before acting on findings.** Worth the cost.
2. **Review setup's `INFO.md` and surface inventory.** Correct auth primitives
   and representative files improve both prompts and coverage decisions.

## When should I use sandbox mode?

`deepsec sandbox process` fans work across [Vercel Sandbox][sb] microVMs
in parallel. Worth it when:

- The repo is large enough that local concurrency saturates your laptop.
- You want results in under an hour on a 5k+ file repo.
- You're running this as a scheduled job in CI/CD.

Otherwise local execution is simpler. Normal initialization already creates
the exact project link and keeps Sandbox-capable credentials in scope, so
switching later requires no additional onboarding. It does not create a
billable Sandbox until you explicitly run a Sandbox command.

[sb]: https://vercel.com/docs/sandbox

## What happens to my code? Is it sent anywhere?

The AI agents read source code from your local repo and send relevant
snippets to the configured LLM provider as part of investigation
prompts. With Vercel AI Gateway, the gateway has zero data retention;
prompts aren't stored. With direct Anthropic, see Anthropic's data
retention policy.

deepsec itself doesn't phone home or report telemetry. The `data/<id>/`
directory stays on your machine unless you explicitly export it.

## Can I run this in CI?

Yes. The natural shape:

```bash
# Cron — full scan every Sunday
pnpm deepsec scan --project-id main --root .
pnpm deepsec process --project-id main --concurrency 5
pnpm deepsec revalidate --project-id main --min-severity HIGH
pnpm deepsec export --project-id main --format json --out findings.json

# Per-PR — incremental scan on changed files only
pnpm deepsec scan --project-id main --root .
pnpm deepsec process --project-id main --filter $CHANGED_PATH_PREFIX
```

The `data/` directory is your state — persist it between CI runs (cache
it as a build artifact) or just re-scan from scratch each time.

## Is it incremental?

Yes:

- `scan` merges new candidates into existing FileRecords; doesn't
  re-investigate already-analyzed files.
- `process` only touches files with `status: "pending"`, unless you
  pass `--reinvestigate` (re-investigate everything) or
  `--reinvestigate <N>` (re-investigate, tagged with wave marker N — a
  later run with the same N skips files already processed in this wave).
- `revalidate` only touches findings without a `revalidation` field
  unless `--force` is set.

## What if a run errors out partway through?

Just re-run the same command. `process` and `revalidate` are safe to
re-run — files that already finished are kept (no double billing), and
only files that didn't finish get picked up. Same is true after a
Ctrl-C, a network blip, a transient model error, or a quota stop. No
state to clean up; no flag to set.

If you specifically want to redo work that already succeeded, that's
what `--reinvestigate` (process) and `--force` (revalidate) are for.

## How do I add a matcher for my codebase?

See [writing-matchers](writing-matchers.md). Short version: hand
your `.deepsec/data/` and the target repo to your coding agent with the
prompt in that doc — it'll spot entry-point coverage gaps the default
matchers miss and write matchers tailored to your codebase.

## What if my codebase is in a language deepsec doesn't have matchers for?

The AI processor is language-agnostic and will investigate any
text-readable source file. The thinner the regex layer, the more the
process stage carries. A few starter matchers for the new language are
worth writing; they front-load file selection so the AI gets the most
promising sites first.

## What if I find a vulnerability in deepsec itself?

See [SECURITY.md](https://github.com/vercel-labs/deepsec/blob/main/SECURITY.md). Don't open a public issue — use
GitHub Security Advisories instead.

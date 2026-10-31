---
title: "Getting started"
description: "Set up deepsec and run your first scan with one command."
---

## Run your first scan

From the root of the repository you want to scan:

```bash
npx deepsec init
```

The command asks you two things, then does the rest on its own:

1. **Which model to use.** You'll see a short list of recommended
   model and reasoning-level combinations, each with its score on the
   DeepSecBench benchmark and its cost relative to the cheapest option.
   Pick one, or choose the last option to type in any model of your own.
2. **How to pay for model calls.** The default routes through Vercel AI
   Gateway — deepsec logs you in to Vercel if needed and sets up a small
   dedicated project to hold credentials (nothing billable is created
   during setup). If you'd rather use your own OpenAI or Anthropic API
   key, no Vercel account is needed — see
   [Using your own API key](#using-your-own-api-key).

After that, deepsec works unattended. It creates a `.deepsec/` folder next
to your code (this is the only thing it adds to your repository), studies
the codebase to understand what it does and where the risky areas are,
runs a fast pattern scan, and then starts the AI review of the flagged
files. Depending on repository size, the AI review can take from minutes
to many hours.

## If it stops partway

Just run the same command again:

```bash
npx deepsec init
```

Deepsec remembers how far it got. Finished steps are skipped and the run
continues where it left off. This is also how you resume after hitting a
cost limit, losing your connection, or pressing Ctrl-C.

If setup cannot cover an inventoried surface, it stops before paid AI
processing and prints the exact inventory, state, generated-matcher, and
resume commands. The state records matcher proposals and rejection reasons.
Re-running setup makes up to two fresh matcher-repair attempts, so a coverage
pause is recoverable after editing `generated-matchers.ts` or the underlying
repository pattern.

## Limiting time and cost

You can bound a run and pick up the rest later:

```bash
npx deepsec init --max-cost-usd 100 --max-duration 2h
```

When a limit is reached, deepsec stops at a safe point. Run the same
command again to continue. Durations need an explicit unit: `ms`, `s`,
`m`, or `h`.

If the run stops because your model provider ran out of credits, deepsec
tells you where to top up; re-run the same command afterwards.

## Reading your results

Everything deepsec produces lives in the `.deepsec/` folder. To get a
readable report:

```bash
cd .deepsec
pnpm deepsec export --format md-dir --out ./findings
```

That writes one markdown file per finding into `./findings`. For a quick
overview instead:

```bash
pnpm deepsec report
```

## Everyday commands

After the first run, work from inside `.deepsec/`:

```bash
pnpm deepsec status       # where things stand
pnpm deepsec scan         # re-run the fast pattern scan (free, no AI)
pnpm deepsec process      # AI review of new or changed candidates
pnpm deepsec revalidate   # re-check findings; cuts false positives
pnpm deepsec export --format md-dir --out ./findings
```

`scan` costs nothing (it's local pattern matching). `process` is the
expensive AI stage. All of these resume cleanly if interrupted, and
re-running them only looks at work that isn't done yet.

## Using your own API key

You don't need a Vercel account to use deepsec with your own API key.
To use your own OpenAI key:

```bash
MY_OPENAI_KEY=... npx deepsec init \
  --agent codex \
  --model-auth direct \
  --ai-provider openai \
  --ai-api-key-env MY_OPENAI_KEY
```

For Anthropic, use `--agent claude --ai-provider anthropic`. Deepsec
stores only the *name* of the environment variable, never the key itself.
Export the variable again for later commands, or put it in
`.deepsec/.env.local`. See [vercel-setup](vercel-setup.md) for other
providers and the full credential reference.

## Using local subscriptions

If the `claude` or `codex` CLI is already logged in on your machine, you
can skip model credentials entirely. Pick **Use local subscriptions** at
the interactive model-access prompt, or pass the flag directly:

```bash
npx deepsec init --model-auth local
```

Deepsec then configures nothing for model access: no API key, no gateway
token, no environment variables. Later commands (`process`,
`revalidate`, `triage`) skip their credential checks and rely on the
machine-wide login — if it's missing, the agent SDK itself reports a
clear error on first use.

Two caveats: the login must exist for the harness you actually run
(`claude` for `--agent claude`, a logged-in `codex` for `--agent codex`),
and `sandbox` commands still need a real API token
(`AI_GATEWAY_API_KEY`), because a machine-local login can't be brokered
into an isolated sandbox.

## Scaffold only

To create the workspace files without running any of the setup:

```bash
npx deepsec init --scaffold-only
```

This writes the `.deepsec/` skeleton — `deepsec.config.ts`,
`package.json`, `README.md`, `AGENTS.md`, `.gitignore`, and
`data/<project>/{INFO.md,SETUP.md,project.json}` for the first project —
and stops. It does not install dependencies, log in to Vercel, pick a
model, scan, or start AI processing.

Use it when you want to review or commit the scaffold before anything
runs, drive the remaining setup from a coding agent, or do the steps by
hand. The command prints the manual path: `pnpm install` inside
`.deepsec/`, an agent prompt for filling in `INFO.md`, then
`pnpm deepsec scan` and `pnpm deepsec process`. You can also run
`pnpm deepsec setup` (or re-run `npx deepsec init`) later to complete
the normal automated flow from where the scaffold left off.

## Two files worth a look

Setup writes two things you may want to review:

- `data/<project>/INFO.md` — a short description of your codebase and its
  security-relevant areas that gets injected into every AI investigation.
  It's meant to be hand-edited: the more accurate it is, the better the
  findings.
- `.deepsec/generated-matchers.ts` — extra scan patterns deepsec generated
  to cover gaps in your codebase. Review and commit this file. To go
  further, see [writing-matchers](writing-matchers.md).

## A note on trust

Treat deepsec like a coding agent: during setup it reads your source code
with an AI agent that authenticates to your model provider. Only run it on
code you trust at that level. For scanning untrusted pull requests, use
the guarded CI patterns in [reviewing-changes](reviewing-changes.md),
or run the work in isolated cloud sandboxes (this part does use a Vercel
account, since the sandboxes run on Vercel):

```bash
pnpm deepsec sandbox process --project-id my-app --sandboxes 10 --concurrency 4
```

Sandboxes never see your real model credentials. The host machine keeps
them and injects them only at the model provider's servers.

## Running from CI or an agent

Without a terminal attached, deepsec automatically runs in headless mode:
it never prompts or opens a browser. The two commands that matter:

```bash
# Preview everything setup would do, without changing anything
npx deepsec init --plan --output json

# Run unattended: accept defaults, pick a model by profile, stream events
npx deepsec init --yes --model-profile value --output jsonl
```

`--model-profile` picks the model for you: `best` (highest benchmark
score), `value` (best score at reasonable cost), or `budget` (cheapest).

Exit code 2 means deepsec needs input it couldn't get headlessly (for
example a Vercel login) — the JSON output says exactly what to do and how
to resume. Exit code 3 means a cost or duration limit was reached; re-run
the same command to continue. In CI, a gateway-routed setup can
authenticate with explicit values instead of a login:

```bash
VERCEL_TOKEN=... VERCEL_TEAM_ID=team_... VERCEL_PROJECT_ID=prj_... \
npx deepsec init --headless
```

Coding agents should read the docs deepsec installs into the workspace,
which always match the installed version: start with
`.deepsec/node_modules/deepsec/SKILL.md`, then the topics under
`.deepsec/node_modules/deepsec/dist/docs/`.

## Scanning more than one repository

A single `.deepsec/` workspace can track several repositories. From the
existing workspace:

```bash
pnpm deepsec init-project ../another-service --id another-service
pnpm deepsec setup --project-id another-service
```

When a workspace has more than one project, pass `--project-id` to the
everyday commands.

## Next

- [configuration](configuration.md) — project, model route, and
  environment configuration.
- [writing-matchers](writing-matchers.md) — improving scan coverage
  with your own matchers.
- [vercel-setup](vercel-setup.md) — credentials, CI setups, and
  troubleshooting the Vercel connection.
- [architecture](architecture.md) — how the pipeline works internally.

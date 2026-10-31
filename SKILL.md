---
name: deepsec
description: Run deepsec, an AI-powered cyber-security vulnerability scanner. Activates when the user invokes /deepsec, asks to run deepsec, or wants to scan their repo, branch, or uncommitted changes for vulnerabilities.
---

# /deepsec — scan this repository with deepsec

`deepsec` is an AI-powered vulnerability scanner.

- Modern AI models are great at security code review.
- Most review solutions only run on pull requests.
- That means most legacy code was never reviewed, and your code from 6
  months ago was reviewed by older models.
- Instead deepsec does security review on ALL of your existing code using
  scaled VM fanout.
- Vercel's deepsec is open source, runs in your own infrastructure, and
  supports strong agent sandboxing.

A fast regex scan flags candidate files, then AI agents investigate each 
candidate in depth and record findings with severity ratings; findings can
later be revalidated, triaged, and exported. Everything it adds to a repository 
lives in a single `.deepsec/` workspace (config, installed package, per-project
data). Because processing runs real AI agents, it costs money in proportion 
to how much code it investigates.

Follow this runbook when the user invokes `/deepsec` or asks for a scan.

## 1. Ask for scope first

Ask the user which scope to process, using a structured question tool if you
have one (AskUserQuestion in Claude Code), otherwise plain text:

- **Uncommitted changes** — working tree + untracked files
- **Diff to main** — changes vs `origin/main` (use `main` if there is no
  `origin` remote)
- **Entire codebase** — warn that this is the expensive option: AI
  processing investigates every candidate file and can cost real money on a
  large repository

Ask before doing anything else so the rest of the flow can run unattended.

## 2. Detect onboarding state

From the repository root:

- **No `.deepsec/deepsec.config.ts`** → not onboarded. Do step 3 in full.
- **`.deepsec/` exists but `.deepsec/node_modules/deepsec` is missing, or a
  previous setup was interrupted** → re-run the init command from step 3; it
  resumes from checkpoints and repairs the install rather than starting over.
- **Otherwise** → onboarded; skip to step 4.

## 3. Onboard without full processing

Onboarding normally ends with an AI processing pass over the whole
repository. Since the user already chose a scope, stop setup after the
coverage phase — that still includes install, login, threat model, matcher
generation, and the final regex scan, but skips the full-repo AI `process`
phase. The scoped processing happens in step 4 instead.

From the repository root, inspect the read-only plan, then run setup:

```bash
npx -y deepsec init --plan --output json
npx -y deepsec init --yes --through coverage --output jsonl
```

Parse every output line as JSON. On a `needs_input` event, show the supplied
message and actions to the user rather than inventing remediation. In
particular, `VERCEL_AUTH_REQUIRED` normally asks the user to run
`npx vercel login`; after they do, follow the returned link action from
inside `.deepsec` (use `npx vercel link` when the user needs to choose a
project), then re-run the same init command. Exit code 2 means input is
needed; exit code 3 means a cost/duration boundary stopped the resumable
run — re-running the same command resumes it. Never expose credential
values, bypass `--yes` prompts on the user's behalf beyond the flag itself,
or launch an interactive login yourself.

## 4. Run the scoped processing

Run from inside `.deepsec/` (the config loader only finds
`deepsec.config.ts` in the current directory or its ancestors; after step 3,
`npx deepsec` resolves to the copy installed there):

| Scope | Command |
| --- | --- |
| Uncommitted changes | `cd .deepsec && npx deepsec process --diff-working` |
| Diff to main | `cd .deepsec && npx deepsec process --diff origin/main` |
| Entire codebase, right after step 3 | `cd .deepsec && npx deepsec process` (the final scan from setup already produced the candidate set) |
| Entire codebase, previously onboarded | `cd .deepsec && npx deepsec scan && npx deepsec process` |

## 5. Interpret results

- Direct-mode (`--diff*`) exit codes: `0` = no net-new findings, `1` = at
  least one net-new finding (not an error), anything else = runtime error.
  Pre-existing findings on touched files are excluded from the gate.
- Summarize any findings for the user, then offer follow-ups (all from
  inside `.deepsec/`): `npx deepsec report`, `npx deepsec revalidate`, and
  `npx deepsec export --format md-dir --out ./findings`.

## Going deeper

After onboarding, full documentation ships with the installed package at
`.deepsec/node_modules/deepsec/dist/docs/` — `getting-started.md`,
`reviewing-changes.md` (direct mode, exit codes, CI gating),
`configuration.md`, `models.md`, and more. Read the relevant doc before
varying the commands above; flags and defaults change between releases.

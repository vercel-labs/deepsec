---
title: "Models"
description: "Choose Codex, Claude, or Pi for process and revalidate runs, and compare models under the same workload."
---

deepsec talks to LLMs through interchangeable agent backends:

| Backend                     | Default model         | Used by                      |
|-----------------------------|-----------------------|------------------------------|
| `codex` (default)           | `gpt-5.5`             | `process`, `revalidate`      |
| `claude`                    | `claude-opus-4-8`     | `process`, `revalidate`      |
| `pi`                        | `zai/glm-5.2`        | `process`, `revalidate` |
| `cursor`                    | `auto`                | `process`, `revalidate`      |
| `claude` (triage)           | `claude-sonnet-4-6`   | `triage` (Claude-only)       |

<<<<<<< HEAD
Interactive one-shot setup recommends five benchmark-backed combinations:
GPT-5.6 Sol, Claude Opus 5, Kimi K3, Grok 4.5, and the current DeepSeek entry.
Deepsec fetches the latest score, reasoning level, harness, and total run cost
from [DeepSecBench](https://vercel.com/ai-gateway/leaderboards/deepsecbench/results.json),
then displays cost relative to the cheapest recommendation. A bundled snapshot
keeps onboarding usable offline and is visibly marked as cached. You can also
paste any custom model slug.

Choose the backend/model non-interactively so repository analysis and the
first processing pass use the same pair:

```bash
npx deepsec init --agent codex --model gpt-5.5
```

For benchmark-backed headless selection, use a profile:

| Profile | Selection rule |
|---|---|
| `best` | Highest compatible DeepSecBench score |
| `value` | Highest score whose run cost is at most 2.5× the cheapest recommendation |
| `budget` | Cheapest compatible recommended combination |

```bash
npx deepsec init --yes --model-profile value --output jsonl
```

Direct OpenAI and Anthropic credentials automatically restrict profiles to a
compatible Codex or Claude harness; custom routes restrict them to Pi.

The built-in backends work with Vercel AI Gateway through the linked
workspace's OIDC credential. The model credential route is independent of the
Vercel/Sandbox project link and is persisted as non-secret `ai` config. Direct
OpenAI/Anthropic and custom Pi routes are documented in
[vercel-setup](vercel-setup.md).
=======
The `codex`, `claude` and `pi` backends work with
[Vercel AI Gateway](https://vercel.com/ai-gateway). One
`AI_GATEWAY_API_KEY` or `VERCEL_OIDC_TOKEN` covers all three. Pi also
accepts provider/model identifiers directly through its model registry,
which makes it useful for comparing gateway/provider behavior under the
same deepsec workload.

The `cursor` backend is different: it drives the **Cursor CLI**
(`cursor-agent`) rather than a model endpoint, so it authenticates
through Cursor (a `cursor-agent login` session or `CURSOR_API_KEY`) and
does not use the gateway. See [the Cursor CLI backend](#the-cursor-cli-backend)
below.
>>>>>>> bb1b541 (feat(agents): add `cursor` CLI agent backend)

## CLI selection

```bash
# Codex (default backend), default model:
pnpm deepsec process --project-id my-app

# Claude with a specific model:
pnpm deepsec process --project-id my-app --agent claude --model claude-sonnet-4-6

# Codex backend, default model:
pnpm deepsec process --project-id my-app --agent codex

# Codex backend, specific model:
pnpm deepsec process --project-id my-app --agent codex --model gpt-5.4

# Pi backend through Vercel AI Gateway, default model:
pnpm deepsec process --project-id my-app --agent pi

# Pi with an AI SDK / AI Gateway style model id:
pnpm deepsec process --project-id my-app --agent pi --model zai/glm-5.2

# Cursor CLI backend (uses your cursor-agent login), default model (auto):
pnpm deepsec process --project-id my-app --agent cursor

# Cursor with an explicit model:
pnpm deepsec process --project-id my-app --agent cursor --model sonnet-4.5

# Triage uses Claude; pass a cheaper model if you want:
pnpm deepsec triage --project-id my-app --model claude-haiku-4-5
```

`--agent`, `--model`, and `--thinking-level` are also accepted on `setup` and
`revalidate`. Setup persists the interactive choice as `defaultAgent`,
`defaultModel`, and `defaultThinkingLevel`, checkpoints the exact combination,
and invalidates affected phases when it changes.

## Thinking level

`process` and `revalidate` accept `--thinking-level` to control how much
reasoning effort the agent spends per batch:

```bash
pnpm deepsec process --project-id my-app --thinking-level high
```

Accepted values: `minimal`, `low`, `medium`, `high`, `xhigh`. The
default is `xhigh` — deepsec optimizes for finding hard bugs, not for
cost. Dial down for cheaper reinvestigation waves or quick smoke runs
over large repos.

The flag maps onto each backend's native dial:

| Backend  | Setting                                     |
|----------|---------------------------------------------|
| `codex`  | model reasoning effort (`minimal`–`xhigh`)  |
| `pi`     | thinking level (`minimal`–`xhigh`)          |
| `claude` | adaptive-thinking effort (`minimal` → `low`, `xhigh` → `max`) |

It applies to the main investigation/revalidation runs only.
Special-purpose follow-up calls (the refusal report, JSON repair) keep
their own fixed, cheap settings regardless of the flag.

Like other subcommand flags, it passes through sandbox mode unchanged:

```bash
pnpm deepsec sandbox process --project-id my-app --sandboxes 30 --thinking-level high
```

## Why these defaults

### `claude-opus-4-8` for `process` and `revalidate`

Investigating a candidate site is a multi-step reasoning task: trace
control flow, recognize an auth boundary, decide whether input is
attacker-controlled, judge severity. Stronger reasoning models pay for
themselves in lower FP rate, even at higher per-call cost. Opus is the
strongest of the Claude family at this kind of code reasoning.

If cost matters more than precision (a 10k-file repo, a quick triaged
starter list), drop to `claude-sonnet-4-6` — same prompt, ~3× cheaper,
~10–20% higher FP rate.

### `gpt-5.5` for the Codex backend

Codex is the OpenAI-flavored agent loop: grep-heavy, fast, runs in a
strict read-only sandbox. `gpt-5.5` is the right balance of reasoning
and cost for that loop. `gpt-5.5-pro` is the most careful Codex
option at significantly higher cost; `gpt-5.4` and below are fine for
follow-up reinvestigation passes.

### Pi for alternate harness runs

Pi uses `@earendil-works/pi-coding-agent` with read-only tools
(`read`, `grep`, `find`, `ls`) and the same deepsec prompt/schema as the
other backends. Its default model is GLM 5.2 through Vercel AI Gateway:

```bash
AI_GATEWAY_API_KEY=vck_...
pnpm deepsec process --project-id my-app --agent pi
```

Normal setup pulls and uses the exact linked workspace's OIDC credential.

For OpenAI-compatible gateways such as Martian, select and persist a custom
route during setup:

```bash
MARTIAN_API_KEY=...
pnpm deepsec setup --project-id my-app \
  --agent pi \
  --model openai/gpt-5.5 \
  --model-auth custom \
  --ai-provider martian \
  --ai-base-url https://api.withmartian.com/v1 \
  --ai-api-key-env MARTIAN_API_KEY \
  --ai-credential-header authorization:bearer
```

Later `process`, `revalidate`, and Sandbox commands resolve the persisted
route. Per-command `--ai-provider`, `--ai-base-url`, `--ai-api-key-env`, and
repeatable `--ai-header name=value` remain available as Pi runtime overrides.

### The Cursor CLI backend

`--agent cursor` drives the [Cursor CLI](https://docs.cursor.com/cli)
(`cursor-agent`) headless. Unlike the other backends, which POST to a
model endpoint over HTTP, Cursor runs its own agent loop — the CLI
does the file reads, globs and shell calls, streams newline-delimited
JSON events, and deepsec parses those into its progress stream and pulls
the findings JSON out of the final message.

```bash
# Log in once (or export CURSOR_API_KEY), then:
cursor-agent login
pnpm deepsec process --project-id my-app --agent cursor
```

- **Auth** comes from the `cursor-agent` session (`~/.cursor`), a
  `CURSOR_API_KEY`, or a `CURSOR_AUTH_TOKEN` session token in the env — the
  last runs unattended in a fresh container with no interactive login.
  deepsec injects nothing; the Vercel AI Gateway env (`AI_GATEWAY_API_KEY`
  etc.) is not used and there is no preflight credential check for this
  backend.
- **Model** defaults to `auto` (Cursor picks). Pass any Cursor model id
  with `--model` (e.g. `sonnet-4.5`, `gpt-5`); run `cursor-agent
  --list-models` to see what your plan exposes.
- **Binary** resolves to `cursor-agent` on `PATH`; override with
  `CURSOR_AGENT_BIN`.
- The CLI is spawned with `--force` (no interactive approvals) and
  `--trust` (skip the workspace-trust prompt) so it runs unattended on a
  fresh checkout; the investigation prompt instructs it to read only.
  Cost is not reported by the CLI, so the per-batch readout shows tokens
  but no `$` figure.

### `claude-sonnet-4-6` for `triage`

Triage buckets findings into P0/P1/P2/skip without re-reading the code
— it just looks at the finding text. That's a cheap task; Opus is
overkill. Sonnet keeps `triage` at ~1¢/finding.

## Refusals

Models occasionally refuse to investigate a candidate — usually when the
source contains an exploit pattern they read as harmful, or when a path
trips a content filter. After every batch, deepsec issues a follow-up
turn asking the agent whether it skipped or declined anything:

> Looking back at the investigation: was there anything you declined
> to fully analyze, refused to look at, or skipped because the content
> or the task felt uncomfortable or out of scope?

The agent answers in a structured JSON shape (see `parseRefusalReport`
in `packages/processor/src/agents/shared.ts`). If `refused: true`, the
batch gets a `refusal` record in run metadata, the per-batch log line
shows a ⚠️ `refusal` marker, and the `refusal` field on the FileRecord
sticks around for audit. No silent skips.

Claude Opus and `gpt-5.5` refuse less than 1% of batches in practice. A
refused batch produces no false negatives — affected files stay
`pending` (revalidation keeps the original verdict), so re-running
`--reinvestigate` against the other backend picks up the dropped sites.
Findings dedupe across agents, so you don't pay twice.

If a single file consistently triggers a refusal (>5% of batches), it's
usually one path with a hard-to-disambiguate exploit pattern. Add it to
`config.json:ignorePaths`, or run that file alone with `--batch-size 1`
so the refusal doesn't take a batch of otherwise-fine files down with
it.

## Future models (e.g. Anthropic Mythos)

The model is a flag, not a baked-in choice. When a stronger reasoning
model lands — Anthropic's Mythos, a next-tier OpenAI release, an
open-weight contender — point `--model` at the new identifier and the
rest of deepsec stays unchanged:

```bash
pnpm deepsec process --project-id my-app --model anthropic-mythos-1
pnpm deepsec process --project-id my-app --agent codex --model gpt-6
pnpm deepsec process --project-id my-app --agent pi --model vercel-ai-gateway/openai/gpt-6
```

Two small integration points:

1. **The model identifier** — whatever string the provider's SDK
   accepts. deepsec passes it through unchanged. No code change needed
   to *use* a new model on either backend.
2. **Pricing for the cost-per-batch readout.** The Claude Agent SDK
   reports cost natively, so new Claude-family models drop in with
   zero code changes. Codex doesn't, so add a line to
   `MODEL_PRICING_USD_PER_M_TOKENS` in
   `packages/processor/src/agents/codex-sdk.ts` for each new
   OpenAI/Codex model. Without it, the batch still runs — the cost
   readout is simply omitted.

When a new model becomes the right default, change the relevant entry
in `packages/deepsec/src/agent-defaults.ts` (one string per backend) and
the `DEFAULT_MODEL` constant in the corresponding agent file. Existing
data and findings are unaffected — deepsec records which agent + model
produced each finding, so a model change shows up cleanly in the
`analysisHistory` of any re-investigated file.

A useful pattern when a new model lands: re-run `process` with
`--reinvestigate <N>` (a wave marker) against the existing
high-severity findings to see whether the new model overturns
verdicts. The wave marker tags the new analysis without losing the
old one.

---
title: "Models"
description: "Choose Codex, Claude, OpenCode, or Pi for process and revalidate runs, and compare models under the same workload."
---

deepsec talks to LLMs through interchangeable agent backends:

| Backend                     | Default model                   | Used by                 |
|-----------------------------|---------------------------------|-------------------------|
| `codex` (default)           | `gpt-5.5`                       | `process`, `revalidate` |
| `claude`                    | `claude-opus-4-8`               | `process`, `revalidate` |
| `opencode`                  | `anthropic/claude-opus-4-8`     | `process`, `revalidate` |
| `pi`                        | `zai/glm-5.2`                   | `process`, `revalidate` |
| `claude` (triage)           | `claude-sonnet-4-6`             | `triage` (Claude-only)  |

The built-in backends work with [Vercel AI Gateway](https://vercel.com/ai-gateway).
One `AI_GATEWAY_API_KEY` or `VERCEL_OIDC_TOKEN` covers Codex, Claude,
OpenCode, and Pi. OpenCode and Pi also accept provider/model identifiers,
which makes them useful for comparing harness and provider behavior under
the same deepsec workload.

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

# OpenCode SDK harness (provider/model is required):
pnpm deepsec process --project-id my-app --agent opencode
pnpm deepsec process --project-id my-app --agent opencode --model openai/gpt-5.5

# Pi backend through Vercel AI Gateway, default model:
pnpm deepsec process --project-id my-app --agent pi

# Pi with an AI SDK / AI Gateway style model id:
pnpm deepsec process --project-id my-app --agent pi --model zai/glm-5.2

# Triage uses Claude; pass a cheaper model if you want:
pnpm deepsec triage --project-id my-app --model claude-haiku-4-5
```

`--agent` and `--model` are also accepted on `revalidate`. Set the
default backend project-wide via `defaultAgent` in
[`deepsec.config.ts`](configuration.md).

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

| Backend    | Setting                                                       |
|------------|---------------------------------------------------------------|
| `codex`    | model reasoning effort (`minimal`–`xhigh`)                    |
| `opencode` | provider variant (Anthropic maps to `high` / `max`)           |
| `pi`       | thinking level (`minimal`–`xhigh`)                            |
| `claude`   | adaptive-thinking effort (`minimal` → `low`, `xhigh` → `max`) |

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

If `.env.local` has `VERCEL_OIDC_TOKEN` from `vercel env pull`, deepsec
uses that as the gateway credential automatically.

For OpenAI/Anthropic-compatible gateways such as Martian, point an
existing Pi provider at the gateway with command-line flags:

```bash
MARTIAN_API_KEY=...
pnpm deepsec process --project-id my-app \
  --agent pi \
  --model openai/gpt-5.5 \
  --ai-provider openai \
  --ai-base-url https://api.withmartian.com/v1 \
  --ai-api-key-env MARTIAN_API_KEY
```

Repeat `--ai-header name=value` for provider-specific headers. There is
no Martian-specific first-class integration; these flags are the generic
provider override path.

### OpenCode SDK harness

OpenCode uses `@opencode-ai/sdk/v2` plus the `opencode-ai` runtime. Each
batch starts a local OpenCode server, creates a session rooted at the target
project, and requests JSON Schema output. The deepsec agent allows only
`read`, `glob`, `grep`, and `list`; shell, edits, network tools, subagents,
external directories, LSP, skills, and MCP-triggered permissions are denied.
The session and server are closed on success, error, or abort.

Models use OpenCode's required `provider/model` form:

```bash
pnpm deepsec process --project-id my-app \
  --agent opencode \
  --model anthropic/claude-opus-4-8
```

For a local run without environment credentials, authenticate a provider in
OpenCode first: run `opencode`, then use `/connect`. Sandbox runs cannot reuse
that local credential store; use AI Gateway or an explicit provider token.
Generic `--ai-provider`, `--ai-base-url`, `--ai-api-key-env`, and
`--ai-header` overrides work for OpenCode as they do for Pi.

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
pnpm deepsec process --project-id my-app --agent opencode --model anthropic/claude-mythos-1
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

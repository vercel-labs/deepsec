# Models

deepsec talks to LLMs through interchangeable agent backends:

| Backend                     | Default model         | Used by                      |
|-----------------------------|-----------------------|------------------------------|
| `codex` (default)           | `gpt-5.5`             | `process`, `revalidate`      |
| `claude`                    | `claude-opus-4-7`     | `process`, `revalidate`      |
| `cursor`                    | `composer-2.5`        | `process`, `revalidate`      |
| `claude` (triage)           | `claude-sonnet-4-6`   | `triage` (Claude-only)       |

`codex` and `claude` route through [Vercel AI Gateway](https://vercel.com/ai-gateway)
by default, so a single token covers Claude **and** Codex. To use
Anthropic or OpenAI directly, point `ANTHROPIC_BASE_URL` /
`OPENAI_BASE_URL` at the provider.

`cursor` uses the [Cursor Agent CLI](https://cursor.com/docs) (`agent` on
PATH). Set `CURSOR_API_KEY` in `.env.local`, or run `agent login` on the
host. List models with `agent --list-models`.

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

# Cursor Agent CLI (local `agent` binary or CURSOR_API_KEY):
pnpm deepsec process --project-id my-app --agent cursor
pnpm deepsec process --project-id my-app --agent cursor --model gpt-5.3-codex-high

# Triage uses Claude; pass a cheaper model if you want:
pnpm deepsec triage --project-id my-app --model claude-haiku-4-5
```

`--agent` and `--model` are also accepted on `revalidate`. Set the
default backend project-wide via `defaultAgent` in
[`deepsec.config.ts`](configuration.md).

## Why these defaults

### `claude-opus-4-7` for `process` and `revalidate`

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

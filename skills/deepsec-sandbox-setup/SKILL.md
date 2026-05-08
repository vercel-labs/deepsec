---
name: deepsec-sandbox-setup
description: Set up AI Gateway and Vercel Sandbox credentials for deepsec — picking between API key vs OIDC token, BYOK, subscription fallback, and troubleshooting auth failures and credit exhaustion. Activates when the user mentions AI_GATEWAY_API_KEY, VERCEL_OIDC_TOKEN, "401 unauthorized", "credits exhausted", or sandbox auth.
---

# Setting up AI Gateway and Vercel Sandbox

deepsec uses two Vercel products. Most users only need the first.

| Product | When you need it |
|---|---|
| **AI Gateway** | Always — for `process` and `revalidate`. One token covers Claude and Codex. Adds provider failover, observability, and zero data retention. |
| **Vercel Sandbox** | Only for `deepsec sandbox process` (distributed scans across microVMs). Skip if running locally. |

Both have a free tier suitable for evaluation. Real scans on
production codebases will exceed the free tier — top up before
kicking off long runs.

## AI Gateway

### Pick a credential

Two ways to authenticate. **If you don't know which to pick, use the
API key** — it's faster to set up and works everywhere, including CI.

| Where you're running | Use this |
|---|---|
| Anywhere | API key (Option A) |
| Local + already linked to a Vercel project (`.vercel/project.json` exists) | OIDC token (Option B) |
| Inside `deepsec sandbox …` | OIDC token (automatic — same token authenticates both) |

### Option A: API key

1. Open the [AI Gateway API Keys page](https://vercel.com/d?to=%2F%5Bteam%5D%2F%7E%2Fai-gateway%2Fapi-keys&title=AI+Gateway+API+Keys).
2. Click **Create key** and follow the prompts.
3. Copy the key (`vck_…`). Keys never expire unless revoked.

In your scanning workspace's `.env.local`:

```bash
AI_GATEWAY_API_KEY=vck_…
```

### Option B: OIDC token

If you're already running Vercel Sandbox, this is automatic — the same
`vercel env pull` that authenticates the sandbox also authenticates
the gateway. Otherwise:

```bash
# In your scanning workspace:
npx vercel link              # link this directory to a Vercel project
npx vercel env pull          # writes VERCEL_OIDC_TOKEN to .env.local
```

deepsec auto-refreshes the token when near expiry (via `@vercel/oidc`),
but the underlying refresh requires `.vercel/project.json` in the
workspace — re-run `vercel env pull` if refresh fails or the directory
moved.

The token expires after **12 hours**.

### Verify

```bash
pnpm deepsec scan --limit 20         # cheap, no AI calls
pnpm deepsec process --limit 5       # exercises the gateway
```

If the second command fails with `Missing AI credentials` or `401`,
see [Troubleshooting](#troubleshooting) below.

### How the credential expansion works

deepsec expands whichever credential it finds (API key first, OIDC
token as fallback) at startup into the four vars the agent SDKs read:

- `ANTHROPIC_AUTH_TOKEN`
- `ANTHROPIC_BASE_URL`
- `OPENAI_API_KEY`
- `OPENAI_BASE_URL`

So a single credential covers both Codex (`--agent codex`, the
default) and Claude (`--agent claude`).

**Any of those four vars set explicitly takes precedence** over the
expansion — useful for mixing direct Anthropic with gateway-routed
OpenAI, etc.

## Costs and credits

The AI Gateway uses pay-as-you-go pricing with **zero markup** on
provider rates. Every Vercel team gets **$5/month free credit** for
evaluation. Full scans on real codebases will exhaust that — top up
before kicking off a long run.

- [Top up credits](https://vercel.com/d?to=%2F%5Bteam%5D%2F%7E%2Fai%3Fmodal%3Dtop-up) — opens the AI dashboard with the top-up modal.
- [Auto top-up](https://vercel.com/docs/ai-gateway/pricing#configure-auto-top-up) — set a threshold; charges automatically when balance dips.
- [Pricing reference](https://vercel.com/docs/ai-gateway/pricing) — model-by-model rates.

Rough budget for a `process` pass with Claude Opus (default settings):

| Files | Approx cost |
|---|---|
| 100   | $25–60   |
| 500   | $130–300 |
| 2,000 | $500–1200 |

Run `--limit 50` first to calibrate before a full pass.

### When credits run out

If `process` or `revalidate` halts because the gateway balance is
exhausted (or a direct provider key ran out), deepsec stops gracefully
— no further batches launch, in-flight batches are cancelled, the
file lock state is preserved. The CLI prints a remediation message
with the right top-up URL.

After topping up, **re-run the same command**. It picks up exactly
where it stopped — files already analyzed are skipped, only the
unfinished ones get re-investigated.

## Subscriptions (Claude Pro / ChatGPT Plus)

If `claude` or `codex` is logged in on this machine, non-sandbox runs
(`process`, `revalidate`, `triage`) can fall back to that subscription
session — no API key needed:

```bash
claude login    # for --agent claude
codex login     # for --agent codex
```

Subscriptions are useful for **evaluating** deepsec but generally do
**not** have enough headroom for full repo scans. The Claude weekly /
5-hour and ChatGPT Plus quotas trip well before a real codebase is
finished. Switch to the gateway (or a direct provider key) once past
evaluation.

## BYOK and direct providers

If you have your own Anthropic / OpenAI agreement, two options:

**Through the gateway (recommended)** — configure
[BYOK](https://vercel.com/docs/ai-gateway/authentication-and-byok#bring-your-own-key-byok)
at the team level. No gateway markup, with failover and observability
on top.

**Bypass the gateway entirely** — set the explicit base URL + token
pairs in `.env.local`:

```bash
# Anthropic direct
ANTHROPIC_AUTH_TOKEN=sk-ant-…
ANTHROPIC_BASE_URL=https://api.anthropic.com

# OpenAI direct
OPENAI_API_KEY=sk-…
# (OPENAI_BASE_URL defaults to api.openai.com — only set for proxies)
```

Mix freely — gateway for Claude, direct for OpenAI, etc. The explicit
values always win over the `AI_GATEWAY_API_KEY` expansion.

## Vercel Sandbox

Only needed for `deepsec sandbox process` and `deepsec sandbox-all`.
Skip this section for local-only.

deepsec supports both auth methods the Sandbox SDK accepts:

| Where you're running | Use this |
|---|---|
| Local development | OIDC token |
| Long-running CI, external infra, server-side cron | Access token |
| Deployed on Vercel | OIDC (automatic, nothing to set) |

### Option A: OIDC token (recommended for local)

```bash
# In your scanning workspace:
npx vercel link              # link this directory to a Vercel project
npx vercel env pull          # writes VERCEL_OIDC_TOKEN to .env.local
```

The token expires after **12 hours**; re-run `vercel env pull` when you
hit auth errors. The Vercel project you link to is just the auth
scope — any project on your team works.

If you go this route, you don't need a separate AI Gateway API key:
the same OIDC token authenticates the gateway automatically.

### Option B: access token (API key)

Use when OIDC isn't viable: external CI/CD, non-Vercel hosting, jobs
that run unattended longer than 12 hours, or any setup where running
`vercel env pull` interactively isn't practical. Three env vars in
`.env.local`:

```bash
VERCEL_TOKEN=…               # https://vercel.com/account/tokens
VERCEL_TEAM_ID=team_…        # Team Settings → Team ID
VERCEL_PROJECT_ID=prj_…      # any project's Settings → General → Project ID
```

The Sandbox SDK reads these directly from `process.env` at
`Sandbox.create()` time.

You can keep both sets of env vars in `.env.local`. The SDK prefers
`VERCEL_OIDC_TOKEN` when present and falls back to access-token mode
otherwise — handy for OIDC locally and access-token in scheduled CI.

### Try a sandbox run

```bash
pnpm deepsec sandbox process --project-id my-app --sandboxes 4
```

If the sandbox can't authenticate, the spawn fails with the SDK's
error. Re-run `vercel env pull` (OIDC) or double-check the three
access-token vars.

## Troubleshooting

| Symptom | What it means | Fix |
|---|---|---|
| `Missing AI credentials for --agent claude` / `codex` | No credential present. | Set `AI_GATEWAY_API_KEY=vck_…` in `.env.local`, or run `claude login` / `codex login`. |
| `401 Unauthorized` from `process` / `revalidate` | Credential present but rejected. | OIDC: re-run `vercel env pull` (12h expiry). API key: regenerate. Confirm `.env.local` is in cwd. |
| `✘ Stopped: Vercel AI Gateway credits exhausted` | Gateway balance is $0. | [Top up](https://vercel.com/d?to=%2F%5Bteam%5D%2F%7E%2Fai%3Fmodal%3Dtop-up), then re-run the same command. |
| `✘ Stopped: Anthropic API credits exhausted` | Direct Anthropic out of credits. | Top up at [Anthropic Console](https://console.anthropic.com/), or switch to the gateway. |
| `✘ Stopped: OpenAI API quota exhausted` | Direct OpenAI out of quota. | Top up in OpenAI dashboard, or switch to the gateway. |
| `✘ Stopped: Claude Pro/Max subscription exhausted` | Hit weekly / 5-hour subscription cap. | Switch to AI Gateway. |
| `✘ Stopped: ChatGPT subscription exhausted` | Hit ChatGPT Plus / Pro quota. | Switch to AI Gateway. |
| Sandbox spawn fails with auth error | OIDC expired (12h) or access-token vars wrong. | Re-run `vercel env pull` (OIDC) or check `VERCEL_TOKEN` / `VERCEL_TEAM_ID` / `VERCEL_PROJECT_ID`. |
| Findings missing cost in the log | Pricing entry missing for a non-default Codex model. | Add to `MODEL_PRICING_USD_PER_M_TOKENS` in `codex-sdk.ts`, or ignore (run still works). |

### After any quota / credit fix

`process` and `revalidate` resume on re-run — there's no recovery
flag, no state to reset. Files already analyzed stay analyzed; only
the unfinished ones get picked up. (To redo finished work, use
`--reinvestigate` for `process` or `--force` for `revalidate`.)

## Hard rules

- **Don't commit `.env.local` to git.** It contains live credentials.
  The `init` scaffold's `.gitignore` already excludes it; don't
  override.
- **Never use a Claude Pro / ChatGPT Plus subscription for a full repo
  scan.** Subscriptions trip well before completion. Use them only
  for evaluation.
- **OIDC tokens expire every 12 hours.** If a long-running CI job
  outlives that, switch to access-token mode (`VERCEL_TOKEN`).

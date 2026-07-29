---
title: "Setting up AI Gateway and Vercel Sandbox"
description: "Use AI Gateway for model access and Vercel Sandbox for distributed scans across microVMs."
---

deepsec uses two Vercel products. Most people only need the first.

| Product | When you need it |
|---|---|
| **[AI Gateway](https://vercel.com/docs/ai-gateway)** | Always — for `process` and `revalidate`. One token covers Claude, Codex, and Pi; the gateway adds provider failover, observability, and zero data retention on top. |
| **[Vercel Sandbox](https://vercel.com/docs/vercel-sandbox)** | Only for `deepsec sandbox process` (distributed scans across microVMs). Skip it if you're running locally. |

Both have a free tier suitable for evaluation. Real scans on production codebases will exceed the free tier — see [Costs and credits](#costs-and-credits) below.

---

## AI Gateway

### Pick a credential

Two ways to authenticate. **If you don't know which to pick, use the API key** — it's faster to set up and works in every environment, including CI.

| Where you're running | Use this |
|---|---|
| Anywhere | API key (Option A) |
| Local + already linked to a Vercel project (`.vercel/project.json` exists) | OIDC token (Option B) |
| Inside `deepsec sandbox …` | OIDC token (automatic — same token authenticates both) |

Reference: [AI Gateway authentication](https://vercel.com/docs/ai-gateway/authentication-and-byok#quick-start).

### Option A: API key

1. Open the [AI Gateway API Keys page](https://vercel.com/d?to=%2F%5Bteam%5D%2F%7E%2Fai-gateway%2Fapi-keys&title=AI+Gateway+API+Keys).
2. Click **Create key** and follow the prompts.
3. Copy the key (`vck_…`). Keys never expire unless you revoke them.

In your scanning workspace's `.env.local`:

```bash
AI_GATEWAY_API_KEY=vck_…
```

### Option B: OIDC token

If you're already running Vercel Sandbox, this is automatic — the same `vercel env pull` that authenticates the sandbox also authenticates the gateway. Otherwise:

```bash
# In your scanning workspace:
npx vercel link              # link this directory to a Vercel project
npx vercel env pull          # writes VERCEL_OIDC_TOKEN to .env.local
```

deepsec auto-refreshes the token when it's near expiry (via `@vercel/oidc`), but the underlying refresh requires `.vercel/project.json` in the workspace — re-run `vercel env pull` if refresh fails or you've moved the directory.

### Verify

Run a small scan to confirm the credential works:

```bash
pnpm deepsec scan --limit 20         # cheap, no AI calls
pnpm deepsec process --limit 5       # exercises the gateway
```

If the second command fails with `Missing AI credentials` or a `401`, see [Troubleshooting](#troubleshooting).

### How it works

deepsec expands whichever credential it finds (the API key first, the OIDC token as fallback) at startup into the four vars the Claude/Codex SDKs read (`ANTHROPIC_AUTH_TOKEN`, `OPENAI_API_KEY`, `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`). Pi reads `AI_GATEWAY_API_KEY` directly through its built-in `vercel-ai-gateway` provider. A single credential covers Codex (`--agent codex`, the default), Claude (`--agent claude`), and Pi (`--agent pi`).

Any of those four vars you set explicitly takes precedence over the expansion — useful for mixing direct Anthropic with gateway-routed OpenAI, etc.

---

## Costs and credits

The AI Gateway uses pay-as-you-go pricing with **zero markup** on provider rates. Every Vercel team gets **$5/month free credit** for evaluation. Full scans on real codebases will exhaust that — top up before kicking off a long run.

- **[Top up credits](https://vercel.com/d?to=%2F%5Bteam%5D%2F%7E%2Fai%3Fmodal%3Dtop-up)** — opens the AI dashboard with the top-up modal pre-selected.
- **[Auto top-up](https://vercel.com/docs/ai-gateway/pricing#configure-auto-top-up)** — set a threshold; the gateway charges automatically when the balance dips below it.
- **[Pricing reference](https://vercel.com/docs/ai-gateway/pricing)** — model-by-model rates.

Rough budget for a `process` pass with Claude Opus (default settings):

| Files | Approx cost |
|---|---|
| 100   | $25–60   |
| 500   | $130–300 |
| 2,000 | $500–1200 |

Run `--limit 50` first to calibrate before a full pass. See [getting-started.md](getting-started.md) for the full cost guide.

### When credits run out

If `process` or `revalidate` halts because the gateway balance is exhausted (or because a direct provider key ran out), deepsec stops gracefully — no further batches launch, in-flight batches are cancelled, the file lock state is preserved. The CLI prints a remediation message with the right top-up URL.

After topping up, **re-run the same command**. It picks up exactly where it stopped — files already analyzed are skipped, only the unfinished ones get re-investigated.

---

## Subscriptions (Claude Pro / ChatGPT Plus)

If `claude` or `codex` is logged in on this machine, non-sandbox runs (`process`, `revalidate`, `triage`) can fall back to that subscription session — no API key needed:

```bash
claude login    # for --agent claude
codex login     # for --agent codex
```

Subscriptions are useful for **evaluating** deepsec but generally do not have enough headroom for full repo scans. The Claude weekly / 5-hour and ChatGPT Plus quotas trip well before a real codebase is finished. Switch to the gateway (or a direct provider key) once you're past evaluation.

---

## BYOK and direct providers

If you have your own Anthropic / OpenAI agreement, two options:

**Through the gateway (recommended)** — configure [Bring Your Own Key (BYOK)](https://vercel.com/docs/ai-gateway/authentication-and-byok#bring-your-own-key-byok) at the team level. No gateway markup, with failover and observability on top.

**Bypass the gateway entirely** — set the explicit base URL + token pairs in `.env.local`:

```bash
# Anthropic direct
ANTHROPIC_AUTH_TOKEN=sk-ant-…
ANTHROPIC_BASE_URL=https://api.anthropic.com

# OpenAI direct
OPENAI_API_KEY=sk-…
# (OPENAI_BASE_URL defaults to api.openai.com — only set it for proxies)
```

Mix freely — gateway for Claude, direct for OpenAI, etc. The explicit values always win over the `AI_GATEWAY_API_KEY` expansion.

### Pi provider overrides

Pi can also point an existing provider at another gateway without a
plugin. This is the intended path for Martian or any OpenAI-compatible
gateway:

```bash
MARTIAN_API_KEY=...
pnpm deepsec process --project-id my-app \
  --agent pi \
  --model openai/gpt-5.5 \
  --ai-provider openai \
  --ai-base-url https://api.withmartian.com/v1 \
  --ai-api-key-env MARTIAN_API_KEY
```

Use `--ai-header name=value` for any extra provider headers; repeat it
as needed. In sandbox mode, deepsec passes only a placeholder env var
into the worker and injects the real token at egress for the
`--ai-base-url` host.

Kimi K3 has a built-in Fireworks preset, so it does not need those routing
flags:

```bash
FIREWORKS_API_KEY=...
pnpm deepsec process --project-id my-app \
  --agent pi \
  --model fireworks/accounts/fireworks/models/kimi-k3
```

The preset selects `https://api.fireworks.ai/inference/v1` and
`FIREWORKS_API_KEY`. It works in sandbox mode too: the orchestrator derives
the same values, gives the worker a placeholder, allowlists
`api.fireworks.ai`, and injects the real bearer token at egress. See
[models.md](models.md#kimi-k3-on-fireworks) for model metadata, pricing, and
override examples.

---

## Vercel Sandbox

Only needed for `deepsec sandbox process` (and `deepsec sandbox-all`). Skip this section if you're running everything locally.

deepsec supports both auth methods the Sandbox SDK accepts. Pick whichever fits your environment — no deepsec config beyond setting the right env vars in `.env.local`. Reference: [Sandbox authentication](https://vercel.com/docs/vercel-sandbox/concepts/authentication).

| Where you're running | Use this |
|---|---|
| Local development on your machine | OIDC token |
| Long-running CI, external infra, server-side cron | Access token |
| Deployed on Vercel | OIDC (automatic, nothing to set) |

### Option A: OIDC token

Recommended for local development. One command pair:

```bash
# In your scanning workspace:
npx vercel link              # link this directory to a Vercel project
npx vercel env pull          # writes VERCEL_OIDC_TOKEN to .env.local
```

The token expires after **12 hours**; re-run `vercel env pull` when you hit auth errors. The Vercel project you link to is just the auth scope — it can be any project on your team.

If you go this route, you don't need a separate AI Gateway API key: the same OIDC token authenticates the gateway automatically.

### Option B: access token (API key)

Use when OIDC isn't viable: external CI/CD, non-Vercel hosting, jobs that need to run unattended for longer than 12 hours, or any setup where running `vercel env pull` interactively isn't practical. Add three env vars to `.env.local`:

```bash
VERCEL_TOKEN=…               # https://vercel.com/account/tokens
VERCEL_TEAM_ID=team_…        # team Settings → Team ID
VERCEL_PROJECT_ID=prj_…      # any project's Settings → General → Project ID
```

The Sandbox SDK reads these directly from `process.env` at `Sandbox.create()` time. References:

- [Creating an access token](https://vercel.com/docs/rest-api#creating-an-access-token)
- [Finding your team ID](https://vercel.com/docs/accounts#find-your-team-id)
- [Finding your project ID](https://vercel.com/docs/project-configuration/general-settings#project-id)

You can keep both sets of env vars in `.env.local`. The SDK prefers `VERCEL_OIDC_TOKEN` when present and falls back to access-token mode otherwise — handy for using OIDC locally and the access-token path in scheduled CI runs without maintaining two configs.

### Try a sandbox run

```bash
pnpm deepsec sandbox process --project-id my-app --sandboxes 4
```

If the sandbox can't authenticate, the spawn fails with the SDK's error. Re-run `vercel env pull` (OIDC) or double-check the three access-token vars.

---

## Troubleshooting

| Symptom | What it means | Fix |
|---|---|---|
| `Missing AI credentials for --agent claude` / `codex` / `pi` | No credential present on this machine. | Set `AI_GATEWAY_API_KEY=vck_…` in `.env.local`; for Claude/Codex local evaluation you can also run `claude login` / `codex login`, and for Pi you can use local Pi auth. |
| `401 Unauthorized` from `process` / `revalidate` | Credential present but rejected. | OIDC: re-run `vercel env pull` (token may have expired — 12 h). API key: regenerate in the dashboard. Confirm `.env.local` is in the cwd deepsec runs from. |
| `✘ Stopped: Vercel AI Gateway credits exhausted` | Gateway balance is $0. | [Top up](https://vercel.com/d?to=%2F%5Bteam%5D%2F%7E%2Fai%3Fmodal%3Dtop-up), then re-run the same command — it resumes from where it stopped. |
| `✘ Stopped: Anthropic API credits exhausted` | Direct Anthropic account out of credits. | Top up at [Anthropic Console](https://console.anthropic.com/), or switch to the gateway. |
| `✘ Stopped: OpenAI API quota exhausted` | Direct OpenAI account out of quota / payment method declined. | Top up in the OpenAI dashboard, or switch to the gateway. |
| `✘ Stopped: Claude Pro/Max subscription exhausted` | Hit the weekly / 5-hour subscription cap. | Switch to AI Gateway — subscriptions don't have enough headroom for full scans. |
| `✘ Stopped: ChatGPT subscription exhausted` | Hit the ChatGPT Plus / Pro quota. | Same — switch to the gateway. |
| Sandbox spawn fails with auth error | OIDC token expired (12 h) or access-token vars wrong. | Re-run `vercel env pull` (OIDC) or double-check `VERCEL_TOKEN` / `VERCEL_TEAM_ID` / `VERCEL_PROJECT_ID`. |
| Findings missing cost in the log | Pricing entry missing for a non-default Codex model. | See [models.md](models.md#future-models-eg-anthropic-mythos). |

### After any quota / credit fix

`process` and `revalidate` resume on re-run — there's no recovery flag to set, no state to reset. Files already analyzed stay analyzed; only the unfinished ones get picked up. (Want to redo finished work? Use `--reinvestigate` for `process` or `--force` for `revalidate`.)

# Setting up AI Gateway and Vercel Sandbox

deepsec talks to two Vercel products:

- **[AI Gateway](https://vercel.com/docs/ai-gateway)** — proxies Claude
  and Codex (one token covers both, with zero-data-retention and high
  fan-out quotas). Required for `process` and `revalidate`.
- **[Vercel Sandbox](https://vercel.com/docs/vercel-sandbox)** —
  microVM execution for `deepsec sandbox process`. Optional; only needed
  for distributed scanning of large codebases.

Both are usable on the free tier for evaluation.

## AI Gateway

### Get a key

1. Open the [AI Gateway API Keys page](https://vercel.com/d?to=%2F%5Bteam%5D%2F%7E%2Fai-gateway%2Fapi-keys&title=AI+Gateway+API+Keys)
   in your Vercel dashboard.
2. Click **Create key** and follow the steps.
3. Copy the key (it starts with `vck_…`). Keys never expire unless
   you revoke them.

Full reference:
[AI Gateway authentication](https://vercel.com/docs/ai-gateway/authentication-and-byok#quick-start).

### Wire it into deepsec

Edit `.env.local` in your scanning workspace:

```bash
AI_GATEWAY_API_KEY=vck_…
```

That's it. deepsec expands this at startup into the four vars the
agent SDKs read (`ANTHROPIC_AUTH_TOKEN`, `OPENAI_API_KEY`,
`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`), so the same key covers both
Claude (`--agent claude-agent-sdk`, the default) and Codex
(`--agent codex`). Any of those four vars you set explicitly takes
precedence over the gateway expansion — useful for mixing direct
Anthropic with gateway-routed OpenAI, etc.

### BYOK (optional)

If you have direct Anthropic / OpenAI agreements you'd rather use,
configure them at the team level via
[Bring Your Own Key (BYOK)](https://vercel.com/docs/ai-gateway/authentication-and-byok#bring-your-own-key-byok).
BYOK requests have no gateway markup and can fall back to gateway
credentials on failure.

To bypass the gateway entirely and hit Anthropic directly:

```bash
ANTHROPIC_AUTH_TOKEN=sk-ant-…
ANTHROPIC_BASE_URL=https://api.anthropic.com
```

## Vercel Sandbox

Only needed for `deepsec sandbox process` (and `deepsec sandbox-all`). Skip
this section if you're running everything locally.

deepsec supports both auth methods the Sandbox SDK accepts. Pick whichever
fits your environment — no deepsec config beyond setting the right env
vars in `.env.local`. Full reference:
[Sandbox authentication](https://vercel.com/docs/vercel-sandbox/concepts/authentication).

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

The token expires after **12 hours**; re-run `vercel env pull` when
you hit auth errors. The Vercel project you link to is just the auth
scope — it can be any project on your team.

### Option B: access token (API key)

Use when OIDC isn't viable: external CI/CD, non-Vercel hosting, jobs
that need to run unattended for longer than 12 hours, or any setup
where running `vercel env pull` interactively isn't practical. Add
three env vars to `.env.local`:

```bash
VERCEL_TOKEN=…               # https://vercel.com/account/tokens
VERCEL_TEAM_ID=team_…        # team Settings → Team ID
VERCEL_PROJECT_ID=prj_…      # any project's Settings → General → Project ID
```

The Sandbox SDK reads these directly from `process.env` at
`Sandbox.create()` time. References:

- [Creating an access token](https://vercel.com/docs/rest-api#creating-an-access-token)
- [Finding your team ID](https://vercel.com/docs/accounts#find-your-team-id)
- [Finding your project ID](https://vercel.com/docs/project-configuration/general-settings#project-id)

You can keep both sets of env vars in `.env.local`. The SDK prefers
`VERCEL_OIDC_TOKEN` when present and falls back to access-token mode
otherwise — handy for using OIDC locally and the access-token path
in scheduled CI runs without maintaining two configs.

### Try a sandbox run

```bash
pnpm deepsec sandbox process --project-id my-app --sandboxes 4
```

If the sandbox can't authenticate, the spawn fails with the SDK's
error. Re-run `vercel env pull` (OIDC) or double-check the three env
vars (access token).

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `401` from `process` / `revalidate` | `AI_GATEWAY_API_KEY` (or `ANTHROPIC_AUTH_TOKEN`) not loaded — confirm `.env.local` is in the cwd deepsec runs from. |
| Sandbox spawn fails with auth error | OIDC token expired (12 h) — re-run `vercel env pull`. Or fall back to access-token mode. |
| `Missing AI credentials for --agent codex` | Set `AI_GATEWAY_API_KEY` (covers both backends) or `OPENAI_API_KEY` directly. |
| Findings missing cost in the log | Pricing entry missing for a non-default Codex model. See [models.md](models.md#future-models-eg-anthropic-mythos). |

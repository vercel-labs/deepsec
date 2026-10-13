---
title: "Project link, Sandbox, and model credentials"
description: "Understand the Vercel project link created by one-shot setup and choose Gateway, direct-provider, or custom model credentials."
---

## One project link, two capabilities

`npx deepsec init` always connects the exact `.deepsec/` workspace to a
Vercel project. That single link supplies the platform identity used for:

- refreshing an OIDC credential for Vercel AI Gateway; and
- creating Vercel Sandbox workers now or later.

There is no separate Sandbox onboarding step. Setup verifies that the exact
workspace link has an OIDC or access-token credential usable by Sandbox, but
does not create a billable Sandbox. Distributed execution remains optional.
The first `sandbox` command performs the authoritative service operation.

The link lives at `.deepsec/.vercel/project.json`. Credentials live in
`.deepsec/.env.local` or the calling process. Both paths are gitignored.
Because `vercel env pull` reads the linked project's development environment,
a dedicated empty Deepsec project is the safest choice.

## Interactive setup

Run from the repository you want to scan:

```bash
npx deepsec init
```

If `.deepsec/.vercel/project.json` is absent, setup runs a pinned Vercel CLI,
prompts for login when necessary, explains the isolated `.deepsec` link, and
offers to create a dedicated Deepsec project or choose an existing one. It
answers Vercel's code-directory and framework questions itself, pulls an OIDC
token, and verifies the selected model route.

An existing exact workspace link is reused. A link in the parent repository
or another ancestor is never silently adopted.

## Headless setup

Headless mode is automatic whenever stdin or stdout is not a TTY. It can also
be requested explicitly with `--headless`; the older `--non-interactive` flag
is an alias. Headless setup never prompts or starts `vercel login`.

An existing exact-workspace link is reused when `.env.local` supplies
`VERCEL_OIDC_TOKEN`. It can also combine that link's team/project IDs with a
`VERCEL_TOKEN`, or refresh OIDC through an authenticated Vercel CLI.

For a new link, `--yes` lets Deepsec use the CLI's current team and create or
reuse a deterministic `deepsec-<project>-<hash>` project. If there is no
current or unique team, JSON/JSONL output returns `VERCEL_SCOPE_REQUIRED` with
the available choices and a `--vercel-team-id` resume argument. If the CLI is
not authenticated, it returns `VERCEL_AUTH_REQUIRED` and tells the calling
agent to ask the user to run `npx vercel login`, then retry.

CI can bypass CLI discovery with the full access-token triple:

```bash
export VERCEL_TOKEN=...
export VERCEL_TEAM_ID=team_...
export VERCEL_PROJECT_ID=prj_...

npx deepsec init --headless
```

Setup writes the non-secret team/project link locally and uses token values
only from the environment or ignored `.env.local`. The same credentials
authorize later `sandbox` commands.

## Choose a model route

Platform authentication and model authentication are separate decisions. The
Vercel project link is always required; the model route can be Gateway,
direct-provider, or custom.

The selected route is persisted as non-secret metadata under `ai` in
`deepsec.config.ts`. Subsequent `setup`, `process`, `revalidate`, and Sandbox
commands rehydrate that route from the named environment variable. Secret
values are never written to config or setup state.

### Vercel AI Gateway (default)

```bash
npx deepsec init
```

The linked project's OIDC credential is the default. You may instead provide
a long-lived Gateway key:

```bash
AI_GATEWAY_API_KEY=vck_... npx deepsec init
```

The route is stored as:

```ts
ai: { mode: "gateway", provider: "vercel" }
```

Deepsec maps the Gateway credential to the environment expected by Codex,
Claude, or Pi. Sandbox workers receive only a placeholder. The real bearer
token is injected at the allowed Gateway host by the host-side broker.

### Your own OpenAI or Anthropic credential

Name the environment variable that holds the key. The name is persisted; the
value is not.

```bash
MY_OPENAI_KEY=... npx deepsec init \
  --agent codex \
  --model-auth direct \
  --ai-provider openai \
  --ai-api-key-env MY_OPENAI_KEY
```

Anthropic works the same way:

```bash
MY_ANTHROPIC_KEY=... npx deepsec init \
  --agent claude \
  --model-auth direct \
  --ai-provider anthropic \
  --ai-api-key-env MY_ANTHROPIC_KEY
```

When you run later commands in a fresh shell, provide the named variable
again or put it in `.deepsec/.env.local`:

```bash
MY_OPENAI_KEY=...
```

Direct OpenAI routes require Codex; direct Anthropic routes require Claude.
Setup rejects incompatible agent/provider combinations before scanning.

### Custom HTTPS provider

Custom routes are supported by the Pi backend. Supply an HTTPS base URL and
describe how the credential should be attached:

```bash
MARTIAN_KEY=... npx deepsec init \
  --agent pi \
  --model openai/gpt-5.5 \
  --model-auth custom \
  --ai-provider martian \
  --ai-api-key-env MARTIAN_KEY \
  --ai-base-url https://api.martian.example/v1 \
  --ai-credential-header x-api-key:raw
```

Use `:bearer` for `Authorization: Bearer …` and `:raw` for provider-specific
raw token headers. HTTP URLs, embedded URL credentials, invalid header names,
and custom routes for Codex/Claude are rejected.

## Credential brokering in Sandbox

Deepsec resolves the real model credential on the host. A worker receives a
fixed placeholder environment value and an egress policy limited to the
selected model host. The Sandbox network transform replaces the placeholder
header at egress; repository-controlled commands cannot read the real token.

This works for Gateway, direct OpenAI/Anthropic, and custom Pi routes. The
broker descriptor is kept in memory and is not written to detached-run state.

This guarantee applies to Vercel Sandbox workers. The one-shot repository
analysis phase runs through a local coding-agent SDK with read-only/no-network
tool policy; treat the target repository as trusted at coding-agent privilege.

## Changing or re-verifying a route

From inside `.deepsec/`:

```bash
pnpm deepsec setup --model-auth direct \
  --agent codex \
  --ai-provider openai \
  --ai-api-key-env MY_OPENAI_KEY
```

Without route flags, `deepsec setup` preserves the route already stored in
config. Setup reuses fresh link/model verification checkpoints, but always
reloads credentials into the current process. Delete or edit the non-secret
`ai` config only when you intentionally want a different route.

## Running distributed work

Once initialization succeeds, no additional auth setup is needed:

```bash
pnpm deepsec sandbox process --project-id my-app --sandboxes 10 --concurrency 4
```

The command uses the same exact project link and persisted model route. For
large multi-project workspaces:

```bash
pnpm deepsec sandbox-all process --sandboxes 30 --concurrency 4
```

## Troubleshooting

| Symptom | Meaning | Fix |
|---|---|---|
| Workspace link is missing | `.deepsec/.vercel/project.json` was removed or setup never linked. | Re-run `deepsec setup`; interactive setup will link again. |
| Non-interactive setup asks for three variables | Access-token mode is incomplete. | Set `VERCEL_TOKEN`, `VERCEL_TEAM_ID`, and `VERCEL_PROJECT_ID` together. |
| Model verification returns 401/403 | The selected model credential is missing, expired, or lacks access. | Refresh OIDC, replace the Gateway key, or provide the configured BYOK variable. |
| Direct route asks for a custom variable | Config stores its name, not its value. | Export it in the fresh shell or add it to `.env.local`. |
| Setup repeats login verification | The link, route, agent, or verification age changed. | Complete the probe; later unchanged runs short-circuit again. |
| Gateway quota is exhausted | Processing stopped before launching more batches. | Add credits or change route, then re-run; processing resumes pending files. |

References: [AI Gateway authentication](https://vercel.com/docs/ai-gateway/authentication-and-byok#quick-start), [Sandbox authentication](https://vercel.com/docs/vercel-sandbox/concepts/authentication).

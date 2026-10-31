---
title: "Configuration reference"
description: "Configure projects, matchers, agents, ownership, and runtime environment values in deepsec.config.ts."
---

deepsec reads `deepsec.config.{ts,mjs,js,cjs}` from the current working
directory, walking up. The CLI inherits whatever the file declares.

```ts
import { defineConfig } from "deepsec/config";
import myPlugin from "@my-org/deepsec-plugin-foo";

export default defineConfig({
  ai: { mode: "gateway", provider: "vercel" },
  projects: [
    { id: "my-app", root: "../my-app" },
    { id: "service", root: "../service", githubUrl: "https://github.com/me/service/blob/main" },
  ],
  plugins: [myPlugin()],
});
```

For a fully-worked example exercising every common field
(`infoMarkdown`, `promptAppend`, `priorityPaths`, an inline plugin),
see [`samples/webapp/deepsec.config.ts`](https://github.com/vercel-labs/deepsec/blob/main/samples/webapp/deepsec.config.ts).

## Top-level fields

| Field | Type | Purpose |
|---|---|---|
| `projects` | `ProjectDeclaration[]` | The codebases deepsec knows about. |
| `plugins` | `DeepsecPlugin[]` | Loaded in order; later plugins override single-slot capabilities. |
| `matchers` | `{ only?: string[]; exclude?: string[] }` | Filter the matcher set used by `scan`. |
| `defaultAgent` | `string` | Default `--agent` value (`codex`, `claude`, or `pi`). See [models](models.md). |
| `defaultModel` | `string` | Default `--model` value selected during setup. |
| `defaultThinkingLevel` | `string` | Default reasoning effort (`minimal` through `xhigh`) selected during setup. |
| `ai` | `ModelRoute` | Non-secret model credential route selected and verified by setup. |
| `dataDir` | `string` | Override the `data/` directory. Defaults to `./data`. |

## Model route

One-shot setup persists how later AI commands should find their credential,
never the credential value itself.

```ts
// Default: linked-project OIDC or AI_GATEWAY_API_KEY
ai: { mode: "gateway", provider: "vercel" }

// User-owned OpenAI key; MY_OPENAI_KEY must exist at runtime
ai: {
  mode: "direct",
  provider: "openai",
  apiKeyEnv: "MY_OPENAI_KEY",
  baseUrl: "https://api.openai.com/v1",
}

// Pi-only custom provider
ai: {
  mode: "custom",
  provider: "martian",
  apiKeyEnv: "MARTIAN_KEY",
  baseUrl: "https://api.martian.example/v1",
  credentialHeader: { name: "x-api-key", scheme: "raw" },
}
```

`process`, `revalidate`, `setup`, and Sandbox orchestration resolve this
route in each fresh process. Explicit per-command Pi provider flags take
precedence. Run `deepsec setup --model-auth …` to change and verify the route
instead of hand-editing it.

## ProjectDeclaration

| Field | Type | Required | Purpose |
|---|---|---|---|
| `id` | `string` | yes | Used as `--project-id` and the data directory name (`data/<id>/`). |
| `root` | `string` | yes | Absolute or relative path to the codebase. |
| `githubUrl` | `string` | no | `https://github.com/owner/repo/blob/branch` — used in exports for clickable links. Auto-detected from `git remote` when omitted. |
| `infoMarkdown` | `string` | no | Repo context injected into AI prompts. Overrides `data/<id>/INFO.md` if both are present. |
| `promptAppend` | `string` | no | Free-form text appended to the system prompt for this project. |
| `priorityPaths` | `string[]` | no | Path prefixes to process first. |

## INFO.md

If `infoMarkdown` isn't set in the config, deepsec looks for
`data/<id>/INFO.md` and injects its contents into the prompt for
`process`, `triage`, and `revalidate`. A few hundred words of repo
context (what the codebase does, the auth shape, the threat model,
known false-positive sources) is the right length. One-shot setup writes and
validates this file automatically. See
[getting-started](getting-started.md) for its required sections and resume
behavior.

## Generated matchers

New workspaces import `generatedMatchersPlugin` from
`generated-matchers.ts`. Setup writes accepted data-only matcher specs into
that file after schema, example, regex-safety, duplicate-slug, coverage, and
breadth validation. Keep the import/plugin entry in config and commit the
generated file after review.

Hand-authored plugins remain additive and can live beside the generated
plugin. See [writing-matchers](writing-matchers.md).

## Matcher filtering

```ts
matchers: {
  only: ["sql-injection", "auth-bypass"],   // run *only* these
  exclude: ["framework-internal-header"],    // skip these
}
```

If `only` is set, `exclude` is ignored. CLI flag `--matchers <slugs>`
overrides the config when both are present.

## Plugin order

Plugins are evaluated in array order:

```ts
plugins: [genericPlugin(), orgPlugin()]
```

For `matchers`, `notifiers`, `agents`: additive — both plugins'
contributions are registered.

For `ownership`, `people`, `executor`: last-write-wins — `orgPlugin()`'s
provider replaces `genericPlugin()`'s.

## Per-project config files

Some legacy fields still live in `data/<id>/config.json`:

```json
{
  "priorityPaths": ["app/api/", "lib/"],
  "promptAppend": "Pay extra attention to the booking flow.",
  "ignorePaths": ["**/legacy/**"]
}
```

This is read by `scan` and by the AI agents. It overrides the same fields
on the project declaration if both are present.

## Environment variables

deepsec reads these from `.env.local` (loaded automatically by the CLI) or
from the process environment.

### Platform authentication

Normal initialization manages these automatically. Non-interactive setup
requires the complete access-token triple.

| Var | Purpose |
|---|---|
| `VERCEL_OIDC_TOKEN` | Interactive linked-project credential used by Gateway and Sandbox. Stored in `.env.local` by setup. |
| `VERCEL_TOKEN` | Non-interactive Vercel access token. |
| `VERCEL_TEAM_ID` | Non-interactive team paired with `VERCEL_TOKEN`. |
| `VERCEL_PROJECT_ID` | Non-interactive project paired with `VERCEL_TOKEN`. |

### Model authentication

| Var | Used by | Purpose |
|---|---|---|
| `AI_GATEWAY_API_KEY` | Gateway route | Optional long-lived alternative to linked-project OIDC. Expanded for the selected agent. |
| `ANTHROPIC_AUTH_TOKEN` | `process`, `revalidate`, `triage` (Claude backend) | API token for the Claude Agent SDK. AI Gateway-issued or Anthropic-issued. Set this if you don't use `AI_GATEWAY_API_KEY`. |
| `ANTHROPIC_BASE_URL` | same | Default (when `AI_GATEWAY_API_KEY` is set): `https://ai-gateway.vercel.sh`. Set to `https://api.anthropic.com` for direct Anthropic. |
| `<ai.apiKeyEnv>` | Direct/custom route | User-chosen variable containing the provider credential. The name is stored in config; the value comes from `.env.local` or the process. |

### Optional

| Var | Used by | Purpose |
|---|---|---|
| `OPENAI_API_KEY` | `--agent codex`, `--agent pi --model openai/...` | Codex SDK token or Pi OpenAI-provider token. Unset is fine if `AI_GATEWAY_API_KEY` is set. |
| `OPENAI_BASE_URL` | `--agent codex` | Default (when `AI_GATEWAY_API_KEY` is set): `https://ai-gateway.vercel.sh/v1`. |
| `PI_CODING_AGENT_DIR` | `--agent pi` | Optional Pi config/auth directory. Defaults to `~/.pi/agent`; local non-sandbox runs can reuse `auth.json` there. |
| `DEEPSEC_AGENT_DEBUG` | both backends | Set to `1` to enable verbose agent logging. |
| `DEEPSEC_DATA_ROOT` | core | Override the data directory location. Equivalent to `dataDir` in config. |

### Plugin-specific

Each plugin documents its own env vars in its README.

## Project-config gating example

For a monorepo where most projects shouldn't get an organization plugin:

```ts
const projectId = process.argv[process.argv.indexOf("--project-id") + 1];
const isInternal = projectId?.startsWith("internal-") ?? false;

export default defineConfig({
  projects: [
    { id: "internal-api", root: "../api" },
    { id: "open-source-app", root: "../app" },
  ],
  plugins: isInternal ? [orgPlugin()] : [],
});
```

The config file is real TypeScript. Any logic at module-load time works.

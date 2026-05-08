---
name: deepsec-configuration
description: Reference for deepsec.config.ts and per-project config.json — projects, plugins, matcher filtering, INFO.md, environment variables. Activates when the user asks what fields a deepsec config takes or how to wire up multiple projects/plugins.
---

# deepsec configuration reference

deepsec reads `deepsec.config.{ts,mjs,js,cjs}` from the current working
directory, walking up. The CLI inherits whatever the file declares.

```ts
import { defineConfig } from "deepsec/config";
import myPlugin from "@my-org/deepsec-plugin-foo";

export default defineConfig({
  projects: [
    { id: "my-app",  root: "../my-app" },
    { id: "service", root: "../service", githubUrl: "https://github.com/me/service/blob/main" },
  ],
  plugins: [myPlugin()],
});
```

## Top-level fields

| Field | Type | Purpose |
|---|---|---|
| `projects` | `ProjectDeclaration[]` | The codebases deepsec knows about. |
| `plugins` | `DeepsecPlugin[]` | Loaded in order; later plugins override single-slot capabilities. |
| `matchers` | `{ only?: string[]; exclude?: string[] }` | Filter the matcher set used by `scan`. |
| `defaultAgent` | `string` | Default `--agent` value (`codex` or `claude`). |
| `dataDir` | `string` | Override the `data/` directory. Defaults to `./data`. |

## ProjectDeclaration

| Field | Type | Required | Purpose |
|---|---|---|---|
| `id` | `string` | yes | Used as `--project-id` and the data directory name (`data/<id>/`). |
| `root` | `string` | yes | Absolute or relative path to the codebase. |
| `githubUrl` | `string` | no | `https://github.com/owner/repo/blob/branch` — used in exports for clickable links. Auto-detected from `git remote` when omitted. |
| `infoMarkdown` | `string` | no | Repo context injected into AI prompts. Overrides `data/<id>/INFO.md` if both are present. |
| `promptAppend` | `string` | no | Free-form text appended to the system prompt for this project. |
| `priorityPaths` | `string[]` | no | Path prefixes to process first. |

## A worked example

```ts
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { type DeepsecPlugin, defineConfig } from "deepsec/config";
import { webappDebugFlag } from "./matchers/webapp-debug-flag.js";
import { webappRouteNoRateLimit } from "./matchers/webapp-route-no-rate-limit.js";

const here = path.dirname(fileURLToPath(import.meta.url));

const webappPlugin: DeepsecPlugin = {
  name: "webapp-internal",
  matchers: [webappDebugFlag, webappRouteNoRateLimit],
};

export default defineConfig({
  projects: [
    {
      id: "webapp",
      root: "./your-app",
      githubUrl: "https://github.com/acme/webapp/blob/main",
      infoMarkdown: fs.readFileSync(path.join(here, "INFO.md"), "utf-8"),
      promptAppend: "Pay extra attention to /api/admin/* and /api/billing/* surfaces.",
      priorityPaths: ["src/api/admin/", "src/api/billing/", "src/lib/auth/"],
    },
  ],
  plugins: [webappPlugin],
});
```

## INFO.md

If `infoMarkdown` isn't set in config, deepsec looks for
`data/<id>/INFO.md` and injects its contents into the prompt for
`process`, `triage`, and `revalidate`.

A few hundred words of repo context (what the codebase does, the auth
shape, the threat model, known false-positive sources) is the right
length. INFO.md is **load-bearing for AI precision** — a generic
template-content INFO.md noticeably hurts findings quality.

The `deepsec init` command prints an agent prompt that walks a coding
agent through writing INFO.md from your codebase. See the
`deepsec-getting-started` skill.

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

- **`matchers`, `notifiers`, `agents`** — additive. Both plugins'
  contributions register.
- **`ownership`, `people`, `executor`** — last-write-wins.
  `orgPlugin()`'s provider replaces `genericPlugin()`'s.

See the `deepsec-writing-plugins` skill for the full plugin contract.

## Per-project config files

Some legacy fields still live in `data/<id>/config.json`:

```json
{
  "priorityPaths": ["app/api/", "lib/"],
  "promptAppend": "Pay extra attention to the booking flow.",
  "ignorePaths": ["**/legacy/**"]
}
```

Read by `scan` and the AI agents. **Overrides the same fields on the
project declaration if both are present.**

## Conditional plugin loading

The config file is real TypeScript — any module-load logic works:

```ts
const projectId = process.argv[process.argv.indexOf("--project-id") + 1];
const isInternal = projectId?.startsWith("internal-") ?? false;

export default defineConfig({
  projects: [
    { id: "internal-api",   root: "../api" },
    { id: "open-source-app", root: "../app" },
  ],
  plugins: isInternal ? [orgPlugin()] : [],
});
```

## Environment variables

Loaded automatically from `.env.local` (in the workspace root) or from
the process environment.

### Required

You need either the one-line shortcut **or** an explicit token for the
backend you're using.

| Var | Used by | Purpose |
|---|---|---|
| `AI_GATEWAY_API_KEY` | all AI commands | Shortcut. Expands at startup into `ANTHROPIC_AUTH_TOKEN` / `OPENAI_API_KEY` / `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL`. One key covers Claude and Codex. Falls back to `VERCEL_OIDC_TOKEN` (from `vercel env pull`) when unset. |
| `ANTHROPIC_AUTH_TOKEN` | `process`, `revalidate`, `triage` (Claude) | API token for the Claude Agent SDK. AI Gateway-issued or Anthropic-issued. |
| `ANTHROPIC_BASE_URL` | same | Default (gateway): `https://ai-gateway.vercel.sh`. Set to `https://api.anthropic.com` for direct. |

### Optional

| Var | Used by | Purpose |
|---|---|---|
| `OPENAI_API_KEY` | `--agent codex` | Codex SDK token. |
| `OPENAI_BASE_URL` | `--agent codex` | Default (gateway): `https://ai-gateway.vercel.sh/v1`. |
| `DEEPSEC_AGENT_DEBUG` | both backends | Set to `1` for verbose agent logging. |
| `DEEPSEC_DATA_ROOT` | core | Override the data directory location. Equivalent to `dataDir` in config. |

Explicit values always win over the `AI_GATEWAY_API_KEY` expansion —
useful for mixing direct Anthropic with gateway-routed OpenAI.

For credential setup, see the `deepsec-sandbox-setup` skill.

## Hard rules

- **Don't put org-specific code in `deepsec.config.ts`.** If it has
  the literal name of an internal helper or service, factor it into a
  plugin instead. See `deepsec-writing-plugins`.
- **Don't override the data directory** with `dataDir` unless you're
  doing something unusual — the relative-path default makes
  multi-machine sync simpler.
- **Per-project `config.json` overrides config-file fields.** When
  both are set, the JSON wins. Don't fight it; pick one location.

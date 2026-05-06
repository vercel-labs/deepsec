# Configuration reference

deepsec reads `deepsec.config.{ts,mjs,js,cjs}` from the current working
directory, walking up. The CLI inherits whatever the file declares.

```ts
import { defineConfig } from "deepsec/config";
import myPlugin from "@my-org/deepsec-plugin-foo";

export default defineConfig({
  projects: [
    { id: "my-app", root: "../my-app" },
    { id: "service", root: "../service", githubUrl: "https://github.com/me/service/blob/main" },
  ],
  plugins: [myPlugin()],
});
```

For a fully-worked example exercising every common field
(`infoMarkdown`, `promptAppend`, `priorityPaths`, an inline plugin),
see [`samples/webapp/deepsec.config.ts`](../samples/webapp/deepsec.config.ts).

## Top-level fields

| Field | Type | Purpose |
|---|---|---|
| `projects` | `ProjectDeclaration[]` | The codebases deepsec knows about. |
| `plugins` | `DeepsecPlugin[]` | Loaded in order; later plugins override single-slot capabilities. |
| `matchers` | `{ only?: string[]; exclude?: string[] }` | Filter the matcher set used by `scan`. |
| `defaultAgent` | `string` | Default `--agent` value (`claude-agent-sdk` or `codex`). See [models.md](models.md). |
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

## INFO.md

If `infoMarkdown` isn't set in the config, deepsec looks for
`data/<id>/INFO.md` and injects its contents into the prompt for
`process`, `triage`, and `revalidate`. A few hundred words of repo
context (what the codebase does, the auth shape, the threat model,
known false-positive sources) is the right length. See
[getting-started.md](getting-started.md) for a coding-agent prompt that
writes a good INFO.md.

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

### Required

You need either the one-line shortcut **or** an explicit token for the
backend you're using.

| Var | Used by | Purpose |
|---|---|---|
| `AI_GATEWAY_API_KEY` | all AI commands | Shortcut. Expands at CLI startup into `ANTHROPIC_AUTH_TOKEN` / `OPENAI_API_KEY` / `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` — one key covers both Claude and Codex through Vercel AI Gateway. Any of those four vars set explicitly takes precedence. Falls back to `VERCEL_OIDC_TOKEN` (from `vercel env pull`) when unset, so users already authenticated for Sandbox don't need a separate gateway key. |
| `ANTHROPIC_AUTH_TOKEN` | `process`, `revalidate`, `triage` (Claude backend) | API token for the Claude Agent SDK. AI Gateway-issued or Anthropic-issued. Set this if you don't use `AI_GATEWAY_API_KEY`. |
| `ANTHROPIC_BASE_URL` | same | Default (when `AI_GATEWAY_API_KEY` is set): `https://ai-gateway.vercel.sh`. Set to `https://api.anthropic.com` for direct Anthropic. |

### Optional

| Var | Used by | Purpose |
|---|---|---|
| `OPENAI_API_KEY` | `--agent codex` | Codex SDK token. Unset is fine if `AI_GATEWAY_API_KEY` is set, or if Codex routes through AI Gateway with the Anthropic token. |
| `OPENAI_BASE_URL` | `--agent codex` | Default (when `AI_GATEWAY_API_KEY` is set): `https://ai-gateway.vercel.sh/v1`. |
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

# AGENTS.md

Pointer file for Codex working in this repo. User-facing docs are
in [README.md](./README.md); contributor docs in
[CONTRIBUTING.md](./CONTRIBUTING.md). Read those first.

## Repo shape

```
packages/
  core/        Types, schemas, plugin contracts, config loader (defineConfig)
  scanner/     Regex matchers + scanning engine
  processor/   AI agent integration (Codex Agent SDK, Codex SDK), enrich, triage, revalidate
  deepsec/      Publishable package: bundled CLI + the `deepsec/config` sub-export + the @vercel/sandbox executor
e2e/           End-to-end tests
```

## Commands

```bash
pnpm install
pnpm test          # all packages, including e2e
pnpm test:unit     # excludes e2e
pnpm -r build      # tsc across all workspaces (typecheck)
pnpm bundle        # esbuild bundle for distribution
pnpm deepsec ...    # the CLI (runs via tsx)
```

## Patterns to keep in mind

- Plugin contracts live in `packages/core/src/plugin.ts`. Internals route
  through `getRegistry()` from `deepsec/config` rather than calling
  organization-specific code directly.
- The CLI auto-loads `deepsec.config.{ts,mjs,js,cjs}` from cwd upward
  (via `packages/deepsec/src/load-config.ts`, jiti).
- New matchers go in `packages/scanner/src/matchers/` and register in
  `matchers/index.ts`. Org-specific matchers belong in a separate
  plugin package, not in this tree.
- The AI prompt template lives in `packages/processor/src/index.ts`. It
  is intentionally generic. Don't add organization-specific context
  there; use `data/<projectId>/INFO.md` or `config.json:promptAppend`.

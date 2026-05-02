# Contributing to deepsec

The most useful contributions are **new matchers** and **new plugins**.
Both have dedicated guides:

- [docs/writing-matchers.md](docs/writing-matchers.md) — grow the matcher
  set with a coding-agent-friendly workflow
- [docs/plugins.md](docs/plugins.md) — plugin authoring reference

## Repo layout

```
packages/
  core/                Types, schemas, plugin contracts, config loader
  scanner/             Regex matchers + scanning engine
  processor/           AI agent integration (Claude SDK, Codex SDK), enrich, triage, revalidate
  deepsec/              Publishable package: bundled CLI + the `deepsec/config` sub-export + the @vercel/sandbox executor
e2e/                   End-to-end tests against a fixture project
fixtures/
  vulnerable-app/      Intentionally vulnerable test data (excluded from lint/knip)
docs/                  User-facing documentation
samples/               Copy-paste starting points for new users
```

## Dev workflow

```bash
pnpm install
pnpm test               # all packages, including e2e
pnpm test:unit          # excludes e2e
pnpm -r build           # tsc across all workspaces (typecheck)
pnpm lint               # biome check
pnpm lint:fix           # biome check --write
pnpm knip               # unused code/dep detection
pnpm deepsec --help      # the CLI (via tsx)
```

Bundle for distribution:

```bash
pnpm bundle             # esbuild → packages/deepsec/dist/{cli,config}.mjs
pnpm test:bundle        # bundle e2e: runs the produced binary as a subprocess
```

All of build, test, lint, and knip must pass before a PR is mergeable.
PRs that touch the publish surface (anything imported via `deepsec/config`)
must also pass `pnpm test:bundle`.

### Live-sandbox e2e (manual)

`e2e/pipeline-sandbox.test.ts` runs the full pipeline against a real
Vercel Sandbox, but with a stub agent inside the sandbox — exercises
bootstrap snapshot, worker spawn, file upload/download, and result
merge without spending model tokens. Gated on `DEEPSEC_E2E_LIVE_SANDBOX=1`
+ Vercel Sandbox credentials, so `pnpm test` skips it by default.

- **In CI**: trigger the
  [E2E live sandbox](.github/workflows/e2e-live-sandbox.yml) workflow
  manually from GitHub Actions. Required repo secrets: `VERCEL_TOKEN`,
  `VERCEL_TEAM_ID`, `VERCEL_PROJECT_ID`. (No AI key needed.)
- **Locally**, when working on sandbox code:
  ```bash
  VERCEL_OIDC_TOKEN=$(grep ^VERCEL_OIDC .deepsec/.env.local | cut -d= -f2) \
  DEEPSEC_E2E_LIVE_SANDBOX=1 \
    pnpm exec vitest run --project e2e e2e/pipeline-sandbox.test.ts
  ```

Run it before PRs that touch `packages/deepsec/src/sandbox/`. The
stub-agent flow doesn't exercise the firewall's credential-brokering
transform (no AI traffic flows), so PRs that touch that path
specifically still warrant a one-off run with `--agent claude-agent-sdk`
+ an AI key.

## Adding a matcher

Short version (full version in [docs/writing-matchers.md](docs/writing-matchers.md)):

1. Create `packages/scanner/src/matchers/<slug>.ts` with a `MatcherPlugin`
   export.
2. Register it in `packages/scanner/src/matchers/index.ts` (import +
   `registry.register(...)`).
3. Run `pnpm deepsec scan --project-id <id> --root <path> --matchers <slug>`
   and check the candidate count is reasonable.
4. `pnpm test` and `pnpm lint`.

Matchers that only make sense for one organization (specific helper
names, internal package imports) go in a plugin instead. See
[docs/plugins.md](docs/plugins.md).

## Authoring a plugin

A plugin can fill any of five slots: `matchers`, `notifiers`, `ownership`,
`people`, `executor`. Read [docs/plugins.md](docs/plugins.md) for the
full guide.

The minimal shape:

```ts
import type { DeepsecPlugin } from "deepsec/config";
import { myMatcher } from "./matchers/my-matcher.js";

export default function myPlugin(): DeepsecPlugin {
  return {
    name: "@my-org/plugin-internal-services",
    matchers: [myMatcher],
  };
}
```


## Style

- Match the existing code style. Lint via [Biome](https://biomejs.dev/);
  `pnpm lint:fix` auto-formats.
- Default to **no comments**. Add one only when the *why* is non-obvious
  (a hidden constraint, a subtle invariant, a workaround). Don't write
  comments that restate the code.
- Keep PRs small and single-purpose. If a matcher add needs a test
  fixture refactor, separate PRs.

## Testing

vitest, run via `pnpm test`. Each package has its own `vitest.config.ts`;
the workspace config in `vitest.workspace.ts` glues them together.

The standard matcher test pattern is in
`packages/scanner/src/__tests__/matchers.test.ts`: a single test that
asserts the matcher fires on a known-vulnerable input and doesn't on a
known-safe one.

## Reporting security issues in deepsec

See [SECURITY.md](SECURITY.md). Don't open public issues for security
problems in the tool itself.

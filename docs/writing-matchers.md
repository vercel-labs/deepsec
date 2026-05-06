# Writing matchers with your coding agent

This doc is for users running deepsec inside a `.deepsec/` workspace —
i.e. you ran `npx deepsec init`, deepsec is installed in
`node_modules/`, and you have a `data/<id>/` directory with at least
one scan in it. The matchers you write here live in *your* config; they
ship alongside deepsec's built-ins for the projects in this workspace.

The intended loop:

```
scan (fast, wide) → process (AI, slow + expensive) → revalidate → write better matchers
```

The default matcher set covers common CWE shapes (SQL injection, SSRF,
path traversal, etc.) and a handful of popular framework shapes
(Next.js, Prisma, Express). It will miss patterns specific to your
codebase: an internal RPC framework, a less common language, a custom
auth helper, a non-default route layout. Custom matchers fill those
gaps.

## When to write one

- A revalidated true-positive needs a matcher to catch siblings on future scans.
- A cluster of `other-*` slugs in `deepsec metrics` points at a real category deepsec has no name for.
- The target repo has **entry points the default matchers don't see**. Check [docs/supported-tech.md](./supported-tech.md) first — your framework may already be covered. If not, a custom matcher fills the gap.
- You have an **organization-specific** pattern (internal auth helper, internal SDK call, custom middleware).

## Where matchers live in your workspace

Custom matchers go inside your `.deepsec/` workspace and are wired up
through an inline plugin in `deepsec.config.ts`. The same shape as a
published plugin, just defined alongside your config.

Reference setup (ships in `node_modules/deepsec/dist/samples/webapp/`):

```
.deepsec/
├── deepsec.config.ts                # inline plugin lists the matchers
└── matchers/
    ├── my-route-no-auth.ts
    └── my-internal-rpc.ts
```

`deepsec.config.ts` looks like:

```ts
import { defineConfig, type DeepsecPlugin } from "deepsec/config";
import { myRouteNoAuth } from "./matchers/my-route-no-auth.js";
import { myInternalRpc } from "./matchers/my-internal-rpc.js";

const myPlugin: DeepsecPlugin = {
  name: "my-app",
  matchers: [myRouteNoAuth, myInternalRpc],
};

export default defineConfig({
  projects: [{ id: "my-app", root: ".." }],
  plugins: [myPlugin],
});
```

Slugs are unique. If your slug collides with a built-in, **your
matcher wins** — useful for swapping in a tighter org-specific version.

If a matcher is genuinely reusable across orgs (e.g. a CWE shape or a
public-framework shape), consider contributing it back to the
[deepsec repo](https://github.com/vercel-labs/deepsec) instead. That
flow is in `CONTRIBUTING.md` of that repo.

## Workflow

### 1. Run a scan + process pass first

You want real `data/` to point the agent at.

```bash
pnpm deepsec scan
pnpm deepsec process --limit 50          # cheap calibration pass
pnpm deepsec revalidate --min-severity HIGH
```

### 2. Hand the workspace to your agent

Open the *parent repo* (the codebase being scanned) in your coding
agent so it can read both the source and `.deepsec/data/`. Then paste:

> I want to add custom matchers to deepsec for this repo. deepsec is
> already installed at `.deepsec/node_modules/deepsec/` and
> `.deepsec/data/<projectId>/` has at least one scan + process pass in
> it.
>
> **Read these first to understand the contract:**
> - `.deepsec/node_modules/deepsec/dist/config.d.ts` — the
>   `MatcherPlugin` interface and the `regexMatcher` helper signature
> - `.deepsec/node_modules/deepsec/dist/samples/webapp/matchers/webapp-debug-flag.ts`
>   — small `normal`-tier matcher
> - `.deepsec/node_modules/deepsec/dist/samples/webapp/matchers/webapp-route-no-rate-limit.ts`
>   — slightly larger matcher that combines a regex sweep with a
>   negative pre-check
> - `.deepsec/node_modules/deepsec/dist/samples/webapp/deepsec.config.ts`
>   — how the inline plugin wires matchers into the config
>
> **Then do the analysis:**
> 1. Walk `.deepsec/data/<projectId>/files/` and look at what the
>    default matchers already cover. Note which `vulnSlug`s show up in
>    `candidates[]` and where the AI's `findings[]` ended up landing
>    after revalidation.
> 2. Compare that against the **target repository** (root above
>    `.deepsec/`). Identify the **major entry points** to the code:
>    public HTTP handlers, RPC entry points, queue consumers, cron
>    jobs, CLI commands, anything that takes untrusted input from the
>    outside. Walk the directories that look like routes/handlers/api,
>    and the framework config files (`next.config.*`,
>    `wrangler.toml`, `serverless.yml`, `Procfile`, `main.go`,
>    `app.py`, etc.) to figure out the entry-point shape.
> 3. Decide which entry points the default matchers **don't reach**.
>    Common gaps:
>    - Frameworks deepsec doesn't ship a glob for (Hono, Elysia,
>      Cloudflare Workers, Bun, Deno, FastAPI, Rails controllers, Go
>      `chi`/`gin`, internal RPC).
>    - Languages with thin built-in coverage (Go, Python, Ruby, Lua,
>      shell, Terraform, SQL).
>    - Custom org-specific wrappers (auth middleware, rate-limit
>      wrappers, request-validation helpers) where deepsec's generic
>      regexes don't know the convention.
> 4. **Then write matchers that cover those gaps.** Prefer one
>    matcher per concern. For each:
>    - **Slug** (kebab-case, names what it flags, e.g.
>      `hono-route-no-auth`, `worker-fetch-handler`).
>    - **Noise tier**:
>      - `precise` — pattern only matches the vulnerable shape, minimal FPs.
>      - `normal` — broader, the AI does the disambiguation. Default.
>      - `noisy` — very wide net; intentionally forces AI review of a
>        path glob (use for entry-point coverage where you just want
>        every file in a glob to be a candidate).
>    - **`filePatterns`** as tight as you can make them
>      (language-specific or directory-anchored). A `noisy` matcher
>      with `**/*.{ts,tsx}` will wedge the scanner on a large repo.
>    - **Regex(es)** that match the shape. Skip test files
>      (`.test.`, `.spec.`, `__tests__`, `_test.go`, etc.).
>    - Save to `.deepsec/matchers/<slug>.ts`. Import types from
>      `"deepsec/config"`.
> 5. Wire the new matchers into the inline plugin in
>    `.deepsec/deepsec.config.ts` (create the plugin if it doesn't
>    exist yet — see `samples/webapp/deepsec.config.ts`).
> 6. Run
>    `pnpm deepsec scan --matchers <slug1>,<slug2>,…` from `.deepsec/`
>    and report how many candidates each matcher fired. Open 3 of the
>    candidates per matcher to spot-check the regex isn't producing
>    obvious false positives.
>
> Bias toward `precise` when you can describe the bug exactly. Use
> `noisy` deliberately when the goal is **entry-point coverage** —
> you'd rather the AI look at every `**/api/**/route.ts` than rely on
> a regex to predict which ones are vulnerable.
>
> Generalize the *shape* of the pattern, not specific identifiers. If
> the repo's auth helper is `requireSession()`, the matcher should
> catch any handler that doesn't call any session/auth helper, not the
> literal string `requireSession`.

The agent will read the contract files (the interface is short — a few
dozen lines for `MatcherPlugin`, plus the `regexMatcher` helper), walk
`data/`, walk the target repo, and write the matchers.

### 3. Run them, tune them, ship them

```bash
pnpm deepsec scan --matchers <new-slug>
```

Watch the candidate count. 0 means too strict (loosen). >100 in a
small repo means too loose (tighten). Typical sweet spots: 1–20 hits
per 1k files for `precise`; 5–100 for `normal`. `noisy` matchers
should match approximately the entry-point count of the framework you
targeted (10s, not 1000s).

When happy, commit `.deepsec/deepsec.config.ts` and
`.deepsec/matchers/`. The next full scan picks them up.

## Noise tiers

| Tier | When | Example |
|---|---|---|
| `precise` | Pattern is unambiguous. | `prisma-raw-sql`: `\$queryRawUnsafe\s*\(` matches only the unsafe API. |
| `normal` | Pattern is broader; AI disambiguates. | `auth-bypass`: flags admin checks and skip-auth strings; AI judges. |
| `noisy` | Every file matching a glob should be reviewed by the AI. | `service-entry-point`: every `**/api/**/route.ts` becomes a candidate. |

Tier also influences ordering. `precise` candidates are processed
first because they have the highest signal per token.

## File globs

Set `filePatterns` tightly. A noisy matcher with `**/*.{ts,tsx}`
wedges the scanner on a 100k-file repo. Prefer:

- Language-specific: `**/*.go`, `**/*.lua`, `**/*.tf`
- Directory-anchored: `**/api/**/*.ts`, `**/services/**/handlers/*.ts`
- Combined: `**/services/**/*.{ts,go}`

## Worked example: covering missing entry points

A team scans a FastAPI service. After a `process` pass,
`data/<id>/files/` shows that the default matchers fired plenty on
`requirements.txt` and a few `*.sql` files but barely touched
`app/routers/*.py`, where the actual HTTP handlers live — the default
glob set is tilted toward TypeScript/Next.js. The AI eventually
investigates a couple of router files via priority paths but skips
most.

1. **Inspect coverage.** Walk `data/<id>/files/app/routers/`. Most
   `FileRecord`s have empty `candidates[]`; the AI never picks them
   up.
2. **Identify entry points.** Each router file decorates handlers
   with `@router.get("/…")`, `@router.post("/…")`, etc. The team's
   convention is that authenticated handlers depend on a
   `current_user: User = Depends(get_current_user)` parameter.
3. **Add a noisy entry-point matcher.** Slug `fastapi-route`,
   `noiseTier: "noisy"`, `filePatterns: ["app/routers/**/*.py",
   "app/api/**/*.py"]`, regex
   `/@\w+\.(get|post|put|delete|patch)\s*\(/`. Every router file
   becomes a candidate; the AI reads them on the next `process` pass.
4. **Add a precise auth-shape matcher.** Slug
   `fastapi-route-no-auth`, `noiseTier: "precise"`, same globs,
   regex sweep for `@\w+\.(get|post|...)` whose subsequent
   `def`/`async def` signature doesn't include `Depends(get_current_user)`
   or `Depends(require_*)`.

Result on the next scan: the AI investigates every router file, and
the precise matcher flags handlers that skip the auth dependency.

## Generic vs plugin vs upstream contribution

Decision tree:

| Catches… | Where |
|---|---|
| An org-specific helper, package, or route layout | Your inline plugin (`.deepsec/matchers/`) |
| A reference to a concrete internal service name | Your inline plugin |
| A CWE shape (path traversal, SSRF, prototype pollution) the public set misses | Consider upstreaming to [deepsec](https://github.com/vercel-labs/deepsec) |
| A shape for a popular OSS framework (Hono, FastAPI, Drizzle) | Upstreaming benefits everyone |

For copy-paste starting points, see
`.deepsec/node_modules/deepsec/dist/samples/webapp/matchers/` —
two real matchers (`webapp-debug-flag.ts`, normal-tier; and
`webapp-route-no-rate-limit.ts`, normal-tier with a negative
pre-check) wired into the inline plugin in
`.deepsec/node_modules/deepsec/dist/samples/webapp/deepsec.config.ts`.

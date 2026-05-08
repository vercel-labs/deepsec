---
name: writing-deepsec-matchers
description: Add custom regex matchers to deepsec to catch entry-point shapes and org-specific patterns the built-in set misses. Activates when the user wants to extend deepsec's coverage for their codebase.
---

# Writing matchers with your coding agent

This skill is for users running deepsec inside a `.deepsec/` workspace
— i.e. they ran `npx deepsec init`, deepsec is installed in
`node_modules/`, and `data/<id>/` has at least one scan in it.

The intended loop:

```
scan (fast, wide) → process (AI, slow + expensive) → revalidate → write better matchers
```

The default matcher set covers common CWE shapes (SQL injection, SSRF,
path traversal, etc.) and a handful of popular framework shapes
(Next.js, Prisma, Express). It will miss patterns specific to a
codebase: an internal RPC framework, a less common language, a custom
auth helper, a non-default route layout. Custom matchers fill those
gaps.

## When to write one

- A revalidated true-positive needs a matcher to catch siblings on future scans.
- A cluster of `other-*` slugs in `deepsec metrics` points at a real category deepsec has no name for.
- The target repo has **entry points the default matchers don't see**. Common gaps: Hono, Elysia, Cloudflare Workers, Bun, Deno, FastAPI, Rails controllers, Go `chi`/`gin`, internal RPC.
- You have an **organization-specific** pattern (internal auth helper, internal SDK call, custom middleware).

## Where matchers live

Custom matchers go inside `.deepsec/` and are wired through an inline
plugin in `deepsec.config.ts`:

```
.deepsec/
├── deepsec.config.ts                # inline plugin lists the matchers
└── matchers/
    ├── my-route-no-auth.ts
    └── my-internal-rpc.ts
```

```ts
// deepsec.config.ts
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

**Slugs are unique. If your slug collides with a built-in, your
matcher wins** — useful for swapping in a tighter org-specific
version.

If a matcher is genuinely reusable across orgs (CWE shape, public
framework), upstream it to <https://github.com/vercel-labs/deepsec>
instead — see that repo's `CONTRIBUTING.md`.

## The MatcherPlugin contract

Open `.deepsec/node_modules/deepsec/dist/config.d.ts` for the live
types. Shape:

```ts
interface MatcherPlugin {
  slug: string;                    // kebab-case, unique
  description: string;
  noiseTier: "precise" | "normal" | "noisy";
  filePatterns: string[];          // globs, keep TIGHT
  requires?: MatcherGate;          // optional tech/sentinel-file gate
  examples?: string[];             // dev-time test cases
  match(content: string, filePath: string): CandidateMatch[];
}

interface CandidateMatch {
  vulnSlug: string;
  lineNumbers: number[];           // 1-indexed
  snippet: string;
  matchedPattern: string;          // the matcher's `label`
}
```

`regexMatcher(slug, patterns, content)` is a helper that handles the
line-by-line iteration, snippet extraction, and dedup for you. Import
it from `"deepsec/config"`.

## Worked example

A debug-flag matcher (real one from `samples/webapp/`):

```ts
import type { CandidateMatch, MatcherPlugin } from "deepsec/config";
import { regexMatcher } from "deepsec/config";

export const webappDebugFlag: MatcherPlugin = {
  slug: "webapp-debug-flag",
  description: "Routes/handlers gated only by env-var debug flags",
  noiseTier: "normal",
  filePatterns: ["src/api/**/*.ts", "src/server/**/*.ts"],
  match(content, filePath): CandidateMatch[] {
    if (/\.(test|spec)\.(ts|tsx)$/.test(filePath)) return [];
    return regexMatcher(
      "webapp-debug-flag",
      [
        { regex: /process\.env\.NODE_ENV\s*!==\s*['"]production['"]/, label: "NODE_ENV guard" },
        { regex: /process\.env\.DEBUG_API\b/, label: "DEBUG_API flag" },
      ],
      content,
    );
  },
};
```

Three things to copy from this:
1. Skip test files via a `filePath` regex at the top of `match()`.
2. Pass an array of `{ regex, label }` to `regexMatcher` — the label
   is what shows up in the AI prompt as `matchedPattern`.
3. `filePatterns` is **directory-anchored** (`src/api/**/*.ts`), not a
   blanket `**/*.ts`. Tight globs keep noisy matchers fast.

## Workflow: hand the workspace to your coding agent

The most efficient way to write a useful matcher set is to let your
coding agent do the analysis. Open the **parent repo** (the codebase
being scanned) in Claude Code / Codex / Cursor / etc. so it can read
both the source and `.deepsec/data/`. Then paste this prompt:

> I want to add custom matchers to deepsec for this repo. deepsec is
> already installed at `.deepsec/node_modules/deepsec/` and
> `.deepsec/data/<projectId>/` has at least one scan + process pass in
> it.
>
> **Read these first to understand the contract:**
> - `.deepsec/node_modules/deepsec/dist/config.d.ts` — the
>   `MatcherPlugin` interface and the `regexMatcher` helper signature.
> - `.deepsec/node_modules/deepsec/dist/samples/webapp/matchers/webapp-debug-flag.ts`
>   — small `normal`-tier matcher.
> - `.deepsec/node_modules/deepsec/dist/samples/webapp/matchers/webapp-route-no-rate-limit.ts`
>   — slightly larger matcher that combines a regex sweep with a
>   negative pre-check.
> - `.deepsec/node_modules/deepsec/dist/samples/webapp/deepsec.config.ts`
>   — how the inline plugin wires matchers into the config.
>
> **Then do the analysis:**
> 1. Walk `.deepsec/data/<projectId>/files/` and look at what the
>    default matchers already cover. Note which `vulnSlug`s show up
>    in `candidates[]`.
> 2. Compare against the **target repository** (root above `.deepsec/`).
>    Identify the major entry points: HTTP handlers, RPC entry points,
>    queue consumers, cron jobs, CLI commands — anything taking
>    untrusted input. Walk routes/handlers/api directories and
>    framework config files (`next.config.*`, `wrangler.toml`,
>    `serverless.yml`, `main.go`, `app.py`, etc.).
> 3. Decide which entry points the default matchers don't reach.
>    Common gaps: frameworks deepsec doesn't ship a glob for; less
>    common languages; org-specific wrappers (auth middleware,
>    rate-limit wrappers, request-validation helpers) where generic
>    regexes don't know the convention.
> 4. **Then write matchers that cover those gaps.** One matcher per
>    concern. For each:
>    - **Slug** (kebab-case, e.g. `hono-route-no-auth`,
>      `worker-fetch-handler`).
>    - **Noise tier**: `precise` (unambiguous shape, minimal FPs) /
>      `normal` (broader, AI disambiguates) / `noisy` (every file in a
>      glob becomes a candidate — use deliberately for entry-point
>      coverage).
>    - **`filePatterns`** as tight as possible. A `noisy` matcher with
>      `**/*.{ts,tsx}` will wedge the scanner.
>    - **Regex(es)** that match the shape. Skip test files
>      (`.test.`, `.spec.`, `__tests__`, `_test.go`, etc.).
>    - Save to `.deepsec/matchers/<slug>.ts`. Import types from
>      `"deepsec/config"`.
> 5. Wire the new matchers into the inline plugin in
>    `.deepsec/deepsec.config.ts` (create the plugin if it doesn't
>    exist yet).
> 6. Run `pnpm deepsec scan --matchers <slug1>,<slug2>,…` from
>    `.deepsec/` and report how many candidates each matcher fired.
>    Open 3 candidates per matcher to spot-check the regex isn't
>    producing obvious false positives.
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

## Tuning loop

```bash
pnpm deepsec scan --matchers <new-slug>
```

Watch the candidate count:
- **0** → too strict, loosen.
- **>100 in a small repo** → too loose, tighten.
- Sweet spots: 1–20 hits per 1k files for `precise`; 5–100 for
  `normal`. `noisy` matchers should match approximately the
  entry-point count of the framework you targeted (10s, not 1000s).

When happy, commit `.deepsec/deepsec.config.ts` and
`.deepsec/matchers/`. The next full scan picks them up.

## Where matchers should live: decision tree

| Catches… | Where |
|---|---|
| Org-specific helper, package, or route layout | Your inline plugin (`.deepsec/matchers/`) |
| Reference to a concrete internal service name | Your inline plugin |
| A CWE shape the public set misses | Consider upstreaming |
| A shape for a popular OSS framework (Hono, FastAPI, Drizzle) | Upstreaming benefits everyone |

## Hard rules

- **Never set `filePatterns: ["**/*.{ts,tsx}"]` on a `noisy` matcher.**
  It will wedge the scanner on any non-trivial repo.
- **Always skip test files in `match()`** with a `filePath` regex
  (`.test.`, `.spec.`, `_test.go`, `__tests__`).
- **Never hardcode a specific identifier when generalizing the shape**
  is possible. Match "any handler that doesn't call any session/auth
  helper", not `requireSession`.
- **Spot-check 3 candidates per new matcher** before committing — a
  loose regex that fires 500 times on a 2k-file repo will burn $100+
  on the next `process` pass.

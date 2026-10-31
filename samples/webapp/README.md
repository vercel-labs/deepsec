# webapp sample

A fictional inventory webapp ("Acme") with deepsec wired up. This is
the **rich reference** — a worked plugin + custom matchers + filled-in
INFO.md showing what a scanning workspace looks like once it's been
loved on for a while.

Files (read in this order):

1. [`package.json`](package.json) — declares `deepsec` as a dependency.
2. [`deepsec.config.ts`](deepsec.config.ts) — loads `INFO.md` inline,
   registers two custom matchers via an in-line plugin.
3. [`matchers/webapp-debug-flag.ts`](matchers/webapp-debug-flag.ts) and
   [`matchers/webapp-route-no-rate-limit.ts`](matchers/webapp-route-no-rate-limit.ts)
   — example custom matchers tuned for this codebase's helpers.
4. [`INFO.md`](INFO.md) — the AI prompt context: auth shape, threat
   model, false-positive sources.
5. [`config.json`](config.json) — optional per-project config
   (`priorityPaths`, `promptAppend`, `ignorePaths`).

## How this relates to one-shot setup

`deepsec init` now creates and installs the workspace, links and verifies
Vercel/Sandbox/model access, writes `INFO.md`, evaluates a structured surface
inventory, and adds safe declarative matchers to `generated-matchers.ts` when
coverage needs them.

This sample demonstrates the next layer: hand-authored matcher code for rules
that need negative checks or richer file logic. Read it for that shape; do not
replace the generated workspace config wholesale.

```bash
# Start and complete setup from your repo root.
npx deepsec init

# Later, when a true-positive needs richer logic than a declarative matcher,
# look at this sample's matchers/*.ts for the shape, and read
# docs/writing-matchers.md. Add the plugin beside generatedMatchersPlugin.
```

## Run the sample as-is

From this directory (works because the monorepo symlinks `deepsec` in
for tests):

```bash
pnpm deepsec scan     --project-id webapp --root ./your-app
pnpm deepsec process  --project-id webapp
```

`deepsec` walks up from cwd to find `deepsec.config.ts`, so any
subdirectory works too.

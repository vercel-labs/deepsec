# FAQ

## How should I install deepsec?

deepsec lives in a `.deepsec/` directory at the root of the repo you
want to scan, checked into git so teammates inherit project context.
From the codebase's repo root:

```bash
npx deepsec init       # creates .deepsec/ + registers this repo
cd .deepsec
pnpm install
```

`.deepsec/` has its own `package.json` and `node_modules/` — separate
from the parent repo's lockfile and tooling. The parent repo only
needs to know `.deepsec/` exists.

To scan another codebase from the same `.deepsec/`, run
`pnpm deepsec init-project <path>`. Each project gets its own
`data/<id>/` subdirectory.

### What about non-JS codebases?

deepsec is polyglot (TS, Go, Python, Lua, Terraform, …). The parent
repo doesn't need to be a Node project — `.deepsec/` is self-contained
and only needs `pnpm` (or `npm` / `yarn`) inside that one directory.

### `.gitignore` policy

The scaffold's `.deepsec/.gitignore` keeps `INFO.md`, `SETUP.md`, and
`deepsec.config.ts` tracked so teammates inherit project context, but
ignores generated state (`data/*/files/`, `data/*/runs/`, etc.).

## How much does it cost?

The expensive stage is `process`. With Claude Opus and default settings
(`--concurrency 5 --batch-size 5`):

| Files | Approx cost | Approx wall time |
|---|---|---|
| 100 | $25–60 | 5–15 min |
| 500 | $130–300 | 25–60 min |
| 2,000 | $500–1200 | 1.5–4 hr |

Costs swing 2–3x based on file complexity. Run `--limit 50` first to
calibrate before committing to a full pass.

`triage` is ~1¢/finding. `revalidate` is comparable to `process`.

## Should I use Claude or Codex?

Both work. Different strengths:

- **Claude (Opus):** strong at reasoning about authorization shapes and
  cross-file flows. The default. Most expensive.
- **Codex (gpt-5.5):** runs in a strict sandbox (read-only, no network).
  Fast at grep-heavy investigations. Cheaper.

Mix them. Run Claude first, then re-process unconvincing findings with
`--agent codex --reinvestigate` for a second opinion. Findings dedupe
across agents.

## Should I use Vercel AI Gateway or Anthropic directly?

Either works. The gateway gives you provider failover, observability,
and zero data retention. One token covers Claude and Codex. For a quick
evaluation, use Anthropic directly. For ongoing production scanning, use
the gateway.

```bash
# Direct Anthropic
ANTHROPIC_AUTH_TOKEN=sk-ant-...
ANTHROPIC_BASE_URL=https://api.anthropic.com

# AI Gateway (recommended)
ANTHROPIC_AUTH_TOKEN=vck_...
ANTHROPIC_BASE_URL=https://ai-gateway.vercel.sh
```

See [vercel-setup.md](vercel-setup.md) for how to get a gateway key
and how to wire up Vercel Sandbox auth (OIDC or access token).

## How accurate is it? What's the FP rate?

After revalidation: ~10–29% on `HIGH+.

Two things help most:

1. **Revalidate `HIGH+` before acting on findings.** Worth the cost.
2. **Write a good `INFO.md` per project.** Even a paragraph describing
   the auth shape and threat model improves precision a lot. See
   [getting-started.md](getting-started.md).

## When should I use sandbox mode?

`deepsec sandbox process` fans work across [Vercel Sandbox][sb] microVMs
in parallel. Worth it when:

- The repo is large enough that local concurrency saturates your laptop.
- You want results in under an hour on a 5k+ file repo.
- You're running this as a scheduled job in CI/CD.

Otherwise local execution is simpler. The sandbox path needs the
`@vercel/sandbox` SDK (already a dep) and a Vercel account.

[sb]: https://vercel.com/docs/sandbox

## What happens to my code? Is it sent anywhere?

The AI agents read source code from your local repo and send relevant
snippets to the configured LLM provider as part of investigation
prompts. With Vercel AI Gateway, the gateway has zero data retention;
prompts aren't stored. With direct Anthropic, see Anthropic's data
retention policy.

deepsec itself doesn't phone home or report telemetry. The `data/<id>/`
directory stays on your machine unless you explicitly export it.

## Can I run this in CI?

Yes. The natural shape:

```bash
# Cron — full scan every Sunday
pnpm deepsec scan --project-id main --root .
pnpm deepsec process --project-id main --concurrency 5
pnpm deepsec revalidate --project-id main --min-severity HIGH
pnpm deepsec export --project-id main --format json --out findings.json

# Per-PR — incremental scan on changed files only
pnpm deepsec scan --project-id main --root .
pnpm deepsec process --project-id main --filter $CHANGED_PATH_PREFIX
```

The `data/` directory is your state — persist it between CI runs (cache
it as a build artifact) or just re-scan from scratch each time.

## Is it incremental?

Yes:

- `scan` merges new candidates into existing FileRecords; doesn't
  re-investigate already-analyzed files.
- `process` only touches files with `status: "pending"`, unless you
  pass `--reinvestigate` (re-investigate everything) or
  `--reinvestigate <N>` (re-investigate, tagged with wave marker N — a
  later run with the same N skips files already processed in this wave).
- `revalidate` only touches findings without a `revalidation` field
  unless `--force` is set.

## How do I add a matcher for my codebase?

See [docs/writing-matchers.md](writing-matchers.md). Short version: hand
a confirmed finding to your coding agent with the prompt in that doc and
it'll write the matcher.

## What if my codebase is in a language deepsec doesn't have matchers for?

The AI processor is language-agnostic and will investigate any
text-readable source file. The thinner the regex layer, the more the
process stage carries. A few starter matchers for the new language are
worth writing; they front-load file selection so the AI gets the most
promising sites first.

## What if I find a vulnerability in deepsec itself?

See [SECURITY.md](../SECURITY.md). Don't open a public issue — use
GitHub Security Advisories instead.

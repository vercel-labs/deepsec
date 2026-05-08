# deepsec skills

Agent skills for [deepsec](https://github.com/vercel-labs/deepsec), the
AI-powered vulnerability scanner. Install with [`npx skills`](https://skills.sh):

```bash
npx skills add vercel-labs/deepsec
```

Or pin a single skill:

```bash
npx skills add vercel-labs/deepsec --skill deepsec-writing-matchers
```

## What's in here

| Skill | When it activates |
|---|---|
| [`deepsec`](deepsec/SKILL.md) | Umbrella — any deepsec question. Routes to the focused skills below. |
| [`deepsec-getting-started`](deepsec-getting-started/SKILL.md) | First scan, install, INFO.md, calibration pass. |
| [`deepsec-writing-matchers`](deepsec-writing-matchers/SKILL.md) | Add a regex matcher to catch entry-points or org-specific shapes the built-ins miss. |
| [`deepsec-writing-plugins`](deepsec-writing-plugins/SKILL.md) | Author a plugin (matchers, notifiers, ownership, people, executor). |
| [`deepsec-pr-review`](deepsec-pr-review/SKILL.md) | `process --diff` for CI gating + a hardened GitHub Actions workflow. |
| [`deepsec-configuration`](deepsec-configuration/SKILL.md) | `deepsec.config.ts` and `data/<id>/config.json` reference. |
| [`deepsec-models`](deepsec-models/SKILL.md) | Pick agent (Claude/Codex), model, handle refusals, drop in future models. |
| [`deepsec-sandbox-setup`](deepsec-sandbox-setup/SKILL.md) | AI Gateway + Vercel Sandbox auth, BYOK, quota recovery, troubleshooting. |
| [`deepsec-data-layout`](deepsec-data-layout/SKILL.md) | `data/<id>/` schema — FileRecord, RunMeta, Finding, AnalysisEntry. jq recipes. |
| [`deepsec-architecture`](deepsec-architecture/SKILL.md) | Pipeline internals, append-only model, sandbox credential brokering, design decisions. |

## How these are scoped

Each skill is **self-contained** — it copies the relevant doc text
inline, so `npx skills add` works without the user having the deepsec
repo or package on disk. The umbrella `deepsec` skill is the front
door; it tells the agent which focused sibling to open for any given
question.

The skills follow the [Agent Skills Specification](https://skills.sh) —
YAML frontmatter with `name` and `description`, then markdown
instructions. Compatible with Claude Code, OpenCode, Cursor, Codex,
and the other agents [`npx skills`](https://skills.sh) supports.

## Authoring style

- **Hard rules** at the bottom of each SKILL.md — the few mistakes
  agents have to actively avoid (e.g. "always run `--limit 50` first";
  "never give `pull-requests: write` to the job that runs PR code").
- **Decision tables** wherever an agent is choosing between options.
- **Real, copy-pasteable code** for matchers, configs, and the
  GitHub Actions workflow — not pseudocode.
- **No external doc links for the core content** — everything an
  agent needs is in the SKILL.md itself. External links go to
  upstream provider docs (Vercel AI Gateway, Anthropic Console, etc.)
  where credentials are obtained.

## Updating these skills

When the upstream `docs/` or `packages/deepsec/SKILL.md` changes,
update the corresponding skill here. The skills are intentionally
copies, not pointers — they need to work standalone after `npx skills
add`.

## License

Apache 2.0 (matches the parent deepsec repo). See [LICENSE](../LICENSE)
and [NOTICE](../NOTICE).

# deepsec

[`deepsec`](https://deepsec.sh) is an agent-powered vulnerability scanner that you can run in your own infrastructure, optimized to perform on-demand review of all code in existing 

`deepsec` is designed to surface hard-to-find issues that have been lurking in applications for a long time. It is configured to use the best models at maximum thinking levels (tunable via `--thinking-level`, see [models](https://github.com/vercel-labs/deepsec/blob/main/docs/models.md)), meaning scans can cost thousands or even tens-of-thousands of dollars for large codebases. Our customers have found the cost worth it for how quickly they were able to patch vulnerabilities that would have otherwise gone unfixed.

For large codebases, work fans out across worker machines in parallel.
If a run is interrupted or errors out partway through, just re-run the same
command — deepsec picks up where it left off, skipping files it already
analyzed and only investigating the rest.

## Get started

From the root of the repository you want to scan:

```bash
npx deepsec init
```

The command guides you through everything. It asks you to pick an AI model
(with benchmark scores and prices to compare) and how to pay for model
usage — your own OpenAI/Anthropic API key, or Vercel AI Gateway — and then
works unattended: it studies your codebase, scans it, and runs the AI
review. The only thing it adds to your repository is a `.deepsec/` folder
where all of its state and findings live.

If the run is interrupted for any reason — Ctrl-C, lost connection, a
spending limit — run `npx deepsec init` again and it continues where it
left off. To cap what a run may spend or how long it may take:

```bash
npx deepsec init --max-cost-usd 100 --max-duration 2h
```

When the scan finishes, get a readable report:

```bash
cd .deepsec
pnpm deepsec export --format md-dir --out ./findings
```

For later scans, work from inside `.deepsec/`:

```bash
pnpm deepsec scan        # fast pattern scan, free
pnpm deepsec process     # AI review of new candidates
pnpm deepsec revalidate  # optional, cuts false-positive rate
pnpm deepsec export --format md-dir --out ./findings
```

The [getting started guide](https://github.com/vercel-labs/deepsec/blob/main/docs/getting-started.md)
covers all of this in more detail, including using your own OpenAI or
Anthropic API key and running from CI or a coding agent.

## Docs

After initialization, agents can read the exact documentation matching the
installed CLI at `.deepsec/node_modules/deepsec/SKILL.md` and
`.deepsec/node_modules/deepsec/dist/docs/`. Setup errors expose these as
absolute machine-readable paths.

- [Getting started](https://github.com/vercel-labs/deepsec/blob/main/docs/getting-started.md) — set up and run your first scan
- [Reviewing changes](https://github.com/vercel-labs/deepsec/blob/main/docs/reviewing-changes.md) — `process --diff` and CI gating
- [Supported technology](https://github.com/vercel-labs/deepsec/blob/main/docs/supported-tech.md) — built-in coverage
- [Generated and hand-authored matchers](https://github.com/vercel-labs/deepsec/blob/main/docs/writing-matchers.md)
- [Configuration](https://github.com/vercel-labs/deepsec/blob/main/docs/configuration.md)
- [Plugins](https://github.com/vercel-labs/deepsec/blob/main/docs/plugins.md)
- [Models](https://github.com/vercel-labs/deepsec/blob/main/docs/models.md)
- [Project link and credentials](https://github.com/vercel-labs/deepsec/blob/main/docs/vercel-setup.md)
- [Architecture](https://github.com/vercel-labs/deepsec/blob/main/docs/architecture.md)
- [Data layout](https://github.com/vercel-labs/deepsec/blob/main/docs/data-layout.md)
- [FAQ](https://github.com/vercel-labs/deepsec/blob/main/docs/faq.md)
- [Samples](https://github.com/vercel-labs/deepsec/tree/main/samples)
- [Contributing](https://github.com/vercel-labs/deepsec/blob/main/CONTRIBUTING.md)

## AI provider

By default, deepsec routes model calls through Vercel AI Gateway, which
gives access to every major model without provider-specific keys. You can
instead bring your own key — OpenAI, Anthropic, or a custom HTTPS
provider — by passing `--model-auth direct` with `--ai-provider` and
`--ai-api-key-env` to `init`; no Vercel account is needed in that mode.
Deepsec only ever stores the *name* of the environment variable holding
your key, never the key itself. See
[project link and credentials](https://github.com/vercel-labs/deepsec/blob/main/docs/vercel-setup.md)
for the full reference.

If a `process` or `revalidate` run halts because the upstream credential
ran out of quota or credits, deepsec stops gracefully and tells you
where to top up. Re-run the same command afterward and it picks up
where it left off.

## Distributed execution (optional)

Large monorepos can fan work across [Vercel Sandbox](https://vercel.com/docs/vercel-sandbox) microVMs:

```bash
pnpm deepsec sandbox process --project-id my-app --sandboxes 10 --concurrency 4
```

Setup already verified the Vercel connection, so this needs no extra
onboarding. The local working tree is tarballed and uploaded; `.git` is
excluded. Model credentials remain host-side and are injected only at the
selected egress host.

## Security model of deepsec itself

Treat `deepsec` like a coding agent with full shell access on the enviroment that it is
running on. It is designed to run on trusted inputs (your source code) but you may still
be concerned about prompt injection due to external dependencies or vendored code.

Running on a sandbox (see above) does limit the potential exposure substantially:

- The API keys for the coding agents are injected outside of the sandbox and hence cannot be exfiltrated
- For the worker sandboxes, network egress from the sandbox is limited to coding agent hosts (Egress is allowed during the bootstrap process, but this does not run the coding agent)

## Workflow reference

| Command         | What it does                                             |
|-----------------|----------------------------------------------------------|
| `scan`          | Find candidate sites with regex matchers (fast, no AI)   |
| `process`       | AI investigation; emits findings + recommendation        |
| `process --diff`| PR-mode: scan + investigate only files changed in a diff |
| `triage`        | Lightweight P0/P1/P2 classification (cheaper model)      |
| `revalidate`    | Re-check existing findings; checks git history for fixes |
| `enrich`        | Add git committer info + (with a plugin) ownership data  |
| `report`        | Markdown + JSON summary for one project                  |
| `export`        | Per-finding JSON or directory of markdown files          |
| `metrics`       | Cross-project counts: severities, vulns by type, TPs     |
| `status`        | Snapshot of the project mirror                           |
| `sandbox <cmd>` | Run any of the above on Vercel Sandbox microVMs          |

## License

Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

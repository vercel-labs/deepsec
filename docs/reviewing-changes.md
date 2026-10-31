---
title: "Reviewing changes (PR mode)"
description: "Use PR mode to investigate only changed files and fail CI when new findings appear."
---

`deepsec process` has a direct-invocation mode for reviewing a specific
set of files — typically the files changed in a pull request. This is
the right tool when you want a fast, scoped read of changed code in CI,
rather than a whole-repo audit.

```bash
deepsec process --diff origin/main
```

## How it differs from a full scan

The standard flow is `scan` → `process` over the entire repo:

| Step      | What it looks at        | What it produces                       |
|-----------|-------------------------|----------------------------------------|
| `scan`    | The full source tree    | Regex candidates per file              |
| `process` | All pending candidates  | AI findings on every flagged file      |

Direct mode collapses both steps into one invocation, scoped to a file
list:

| Step              | What it looks at                | What it produces                                           |
|-------------------|---------------------------------|------------------------------------------------------------|
| Resolve files     | `--diff` / `--files` / stdin    | A POSIX-relative file list under `rootPath`                |
| Scoped scan       | Only the listed files           | Candidates as **signals** for the prompt (best-effort)     |
| Always-process    | The same listed files           | AI findings — even on files no matcher hit                 |

The scoped scan still runs because regex hits are useful prompt anchors
for the agent. Files with no hits still get a record and still get
investigated as a holistic review — no signals, no scanner anchoring,
just the agent reading the file.

## Flags

All five sources are mutually exclusive:

```text
--diff <ref|range>     Investigate `git diff --name-only <ref>` (e.g. origin/main, HEAD~1..HEAD)
--diff-staged          Investigate the index vs HEAD
--diff-working         Investigate uncommitted + untracked files
--files <csv>          Investigate this comma-separated path list
--files-from <path>    Read newline-delimited paths from <path> (or "-" for stdin)
```

Other knobs:

```text
--no-ignore            Bypass the default ignore filter (test files, dist/, node_modules/, …)
--comment-out <path>   Write a PR-comment-shaped markdown summary to <path> (only when findings exist)
--project-id <id>      Override the project id (auto-derived from rootPath basename otherwise)
--root <path>          Override the project root (defaults to cwd or deepsec.config.ts)
```

The usual `--agent`, `--model`, `--concurrency`, `--batch-size`,
`--max-turns`, `--thinking-level` flags work the same as in standard
mode.

## Auto-created projects

You don't need to run `deepsec init` first. When invoked with one of the
direct-mode flags, `process` will:

1. Use `--project-id` if you pass one. If it's already declared in
   `deepsec.config.ts`, the declared root is used; otherwise `--root`
   (or the current working directory) is used.
2. Otherwise, derive the id from the basename of the resolved root.
3. Write `data/<id>/project.json` if it doesn't already exist.

Auto-creation is one-line and non-destructive — it never modifies your
`deepsec.config.ts`. It just ensures `data/<id>/` exists so file
records, run metadata, and the optional PR-comment markdown have
somewhere to land.

## Exit codes

| Code | Meaning                                          |
|------|--------------------------------------------------|
| `0`  | No findings produced in this run                 |
| `1`  | At least one finding was produced                |
| `≠1` | Runtime error (bad input, missing credentials, …)|

This makes direct mode a drop-in CI gate: the job fails when the agent
finds something. **Net-new findings only** count toward the exit code —
re-running on a file with existing findings doesn't fail the build
unless something new is surfaced. Pre-existing findings (from a prior
full scan, or earlier PR review runs) on touched files are intentionally
excluded so the gate matches the change-scoped review model.

## PR comments

`--comment-out <path>` writes a markdown body summarizing the **net-new
findings** from this run — same scope as the exit-code gate. Findings
already on touched files (from earlier full scans or prior PR reviews)
aren't re-surfaced. Descriptions and recommendations are truncated
(600 / 400 chars) so a multi-finding PR doesn't blow past GitHub's
65 KiB comment limit; the full text stays in `data/<id>/files/`.

The file is only written when there are findings, so a green run leaves
nothing on disk and your "post comment" step can short-circuit on
`if: hashFiles('comment.md') != ''`.

This is the workflow we use to review our own PRs — copy it as-is:

```yaml
name: deepsec

on: pull_request

permissions:
  contents: read

jobs:
  analyze:
    if: github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # need history for `git diff origin/<base>`

      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with: { node-version: 24, cache: pnpm }

      - run: pnpm install --frozen-lockfile
      - run: npm install -g @anthropic-ai/claude-code

      - id: deepsec
        env:
          AI_GATEWAY_API_KEY: ${{ secrets.AI_GATEWAY_API_KEY }}
          CLAUDE_CODE_EXECUTABLE: claude
        run: |
          pnpm deepsec process \
            --diff origin/${{ github.event.pull_request.base.ref }} \
            --comment-out comment.md

      - if: always() && hashFiles('comment.md') != ''
        uses: actions/upload-artifact@v4
        with:
          name: deepsec-comment
          path: comment.md
          retention-days: 1

  comment:
    needs: analyze
    if: always() && needs.analyze.result == 'failure'
    runs-on: ubuntu-latest
    timeout-minutes: 5
    permissions:
      contents: read
      pull-requests: write
    steps:
      - id: dl
        continue-on-error: true
        uses: actions/download-artifact@v4
        with:
          name: deepsec-comment

      - if: steps.dl.outcome == 'success'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: fs.readFileSync('comment.md', 'utf8'),
            });
```

### How it works

- **Two-job split.** `analyze` runs PR-controlled code (the
  user's `pnpm install`, their config, their source) with the AI
  gateway secret in scope but **no write permissions on the repo**.
  `comment` has `pull-requests: write` but never runs any PR code —
  it consumes only the sanitized `comment.md` artifact. A malicious
  PR can't combine "execute arbitrary code" with "write to the
  repository" in a single privileged step.
- **Same-repo-only gate.** `if: github.event.pull_request.head.repo.full_name == github.repository`
  skips fork PRs entirely. Forks already don't receive repo secrets
  under `pull_request`, so the deepsec step would just fail on
  missing credentials anyway — this gate is purely a UX cleanup
  (fork PRs show "skipped" instead of red ❌ from a doomed run).
- **`fetch-depth: 0`** — needed so `git diff origin/<base>` can
  resolve against the merge base; the default shallow clone doesn't
  have it.
- **`npm install -g @anthropic-ai/claude-code`** — the Claude Code CLI
  is what the SDK actually drives. Installing it globally + setting
  `CLAUDE_CODE_EXECUTABLE: claude` skips the SDK's bundled-binary
  resolution, which can fail on Linux under some package managers.
- **`pnpm deepsec`** — swap for `npx -y deepsec`, `npm exec deepsec`,
  or `yarn deepsec` to match your package manager.
- **`comment.md` is uploaded only when findings exist** —
  `--comment-out` writes nothing on a green run, so the upload step's
  `hashFiles` check skips and the `comment` job downloads no
  artifact. That keeps the post-comment job a no-op when there's
  nothing to say.

### Threat model notes

- **Don't grant `pull-requests: write` to a job that runs PR code.**
  The two-job pattern above keeps PR code in the no-write `analyze`
  job. If you're tempted to collapse them, remember that a PR can
  add arbitrary code to its own `package.json` postinstall scripts
  or to a project config file that the CLI loads — both run before
  any of your own steps.
- **Pin actions to full SHAs in production.** This example uses
  major-version tags (`@v4`) for readability. For a hardened
  deployment, swap each tag for the action's full commit SHA so a
  compromised tag can't pivot into your secret-bearing job. See
  [GitHub's hardening guide](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions).
- **The AI gateway secret still flows through PR code.** Even with
  the job split, `analyze` has the secret in env while running
  PR-controlled `pnpm install`. The `author_association` gate is
  what prevents that from being a vulnerability. If you want
  defense-in-depth, run `analyze` only after a label is applied
  (e.g. `if: contains(github.event.pull_request.labels.*.name, 'review-ok')`).

## Cost notes

Wide diffs are expensive — each file pays for an AI investigation. For
PRs against `main`, scope to the merge base (`origin/main`), not the
entire branch ancestry. If a touched file isn't worth investigating
(generated code, fixtures), add it to your existing ignore patterns or
drop it via a custom `--files-from` script:

```bash
git diff --name-only origin/main \
  | grep -v '^generated/' \
  | deepsec process --files-from -
```

## When NOT to use direct mode

- For the initial sweep of a large repo: full `scan` + `process` orders
  by noise tier, parallelizes better, and benefits from the
  whole-repo signal in matcher gating. Direct mode is for incremental
  review.
- For revalidating existing findings: use `revalidate` with its own
  filters.

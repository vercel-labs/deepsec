---
name: deepsec-architecture
description: How deepsec is built — the scan/process/revalidate/enrich pipeline, append-only on-disk model, plugin extension points, sandbox credential brokering, and core design decisions. Activates when the user asks how deepsec works internally, what a stage actually does, or why a design choice was made.
---

# deepsec architecture

## Pipeline

```
       scan          process        revalidate          enrich           export
        │              │                │                │                  │
        ▼              ▼                ▼                ▼                  ▼
  candidates  →   findings    TP/FP/Fixed verdict  →  +committers  →  JSON / md-dir
                                                       +ownership
```

Each stage is a separate CLI subcommand and reads/writes a consistent
on-disk representation. **Stages are idempotent** — re-running merges
new information rather than overwriting.

## On-disk layout

```
data/<projectId>/
├── project.json              # rootPath, githubUrl (auto-managed)
├── INFO.md                   # repo context injected into AI prompts
├── config.json               # priorityPaths, promptAppend, ignorePaths (optional)
├── files/                    # one JSON per scanned file (FileRecord)
│   └── path/to/file.ts.json
├── runs/                     # one JSON per run (RunMeta)
│   └── 20260429-abcd.json
└── reports/                  # generated reports
```

Each `FileRecord` is the source of truth for everything deepsec knows
about a single source file: candidate matches, AI findings, analysis
history, git committer info, ownership.

The **merge model is additive**: every stage adds to the FileRecord. A
re-scan merges new candidates into the existing set; a re-process
appends to `analysisHistory` and merges new findings; revalidation tags
existing findings with verdicts. Nothing is overwritten or deleted.

For full schemas, see the `deepsec-data-layout` skill.

## Stage details

### scan

- **What it does:** Glob the project root, run regex matchers on every
  matched file, write `candidates` to each FileRecord.
- **Cost:** Free (no AI). ~15s for 2k files.
- **Inputs:** Project root, matcher set (built-ins + plugin contributions).
- **Outputs:** `data/<id>/files/**/*.json` with `candidates` populated and
  `status: "pending"`.

The matcher set is built per-run from the default registry plus any
matchers contributed by active plugins. **Plugin matchers can override
built-ins** by reusing the same slug.

### process

- **What it does:** Pick batches of pending files, send each batch to the
  configured AI agent backend with the system prompt + INFO.md, parse
  the agent's JSON response into `Finding`s, write back to each
  FileRecord.
- **Cost:** $$. The expensive stage.
- **Inputs:** FileRecords with `status: "pending"`, `INFO.md`, the prompt
  template (`packages/processor/src/index.ts:DEFAULT_PROMPT_TEMPLATE`).
- **Outputs:** FileRecord `findings[]` populated, `status: "analyzed"`,
  `analysisHistory[]` appended.

Two agent backends, both routed through Vercel AI Gateway by default:

| `--agent` | SDK | Default model |
|---|---|---|
| `codex` (default) | `@openai/codex-sdk` | `gpt-5.5` |
| `claude` | `@anthropic-ai/claude-agent-sdk` | `claude-opus-4-7` |

Same prompt, same JSON output schema. You can mix backends within a
project — re-process a file with a different agent and the second
run's findings get merged with the first.

**Concurrency:** `--concurrency 5 --batch-size 5` means 5 batches in
flight, 5 files per batch = 25 files in the air at peak. The processor
claims files atomically via `lockedByRunId` so multiple workers can
run in parallel without stepping on each other.

### revalidate

- **What it does:** Re-check existing findings for false positives. The
  agent re-reads the code, consults git history (was this fixed?), and
  emits a verdict: `true-positive`, `false-positive`, `fixed`, or
  `uncertain`.
- **Cost:** $$. Comparable to `process`. Worth running on HIGH+.
- **Inputs:** Findings with no `revalidation` field, or with `--force`.
- **Outputs:** `revalidation: { verdict, reasoning, … }` on each finding.

Empirically reduces FP rate by 50%+ on most repos.

### enrich

- **What it does:** Attach git committer info and (with a plugin)
  ownership data to FileRecords with findings.
- **Cost:** Free if no ownership plugin; otherwise one HTTP round-trip
  per file to the ownership provider.
- **Inputs:** FileRecords with findings, the project's git history.
- **Outputs:** `gitInfo: { recentCommitters, ownership }` on each record.

### export / report / metrics

Read-only stages. Don't modify FileRecords; just shape the data for
human or downstream consumption.

- **export** — flat list of findings as JSON or directory of markdown.
- **report** — per-project markdown summary + JSON.
- **metrics** — cross-project counts and TP rates.

## Plugin architecture

Five extension points, all defined in `packages/core/src/plugin.ts`:

| Slot | Behavior |
|---|---|
| `matchers` | additive |
| `notifiers` | additive |
| `agents` | additive |
| `ownership` | single-slot (last plugin wins) |
| `people` | single-slot |
| `executor` | single-slot |

A plugin registers via `deepsec.config.ts`:

```ts
export default defineConfig({
  plugins: [vercel(), myPlugin()],
});
```

The CLI calls `loadConfig()` before parsing args, builds a
`PluginRegistry` from the active plugins, and stashes it on a
module-level singleton (`getRegistry()`). All internal code consults
the registry rather than hard-coding integrations.

See the `writing-deepsec-plugins` skill for authoring details.

## Distributed execution (Vercel Sandbox)

`pnpm deepsec sandbox process --sandboxes N` distributes work across N
Vercel Sandbox microVMs:

1. **Tarball bundling** — three tarballs (app, target source, data)
   prepared in parallel, respecting `.gitignore` via `git ls-files`.
   Streamed to disk with SHA256 checksums to bound memory.
2. **File partitioning** — partitioner loads all project file records,
   filters eligibility by command (process: pending/error files;
   revalidate: findings ≥ `--min-severity`), sorts by priority paths
   and severity, splits into N disjoint partitions balanced by record
   count.
3. **Bootstrap & spawn** — for each sandbox: extract tarballs, install
   deps, mark setup complete, spawn the deepsec CLI with `--manifest
   <path>` pointing at the partition's file list.
4. **Result download** — tar files modified in `data/<projectId>/`
   newer than the setup marker; extract with strict path allowlist;
   merge sandbox writes onto local records.

### Credential brokering

Real API tokens never enter the sandbox. Instead:

- Sandbox env sees a placeholder `BROKERED_TOKEN_PLACEHOLDER`.
- The Vercel firewall network policy injects a `Deepsec-Credentials`
  header with the real tokens.
- An in-sandbox `request-proxy.mjs` strips the placeholder and injects
  the real token on every upstream request.
- The proxy also strips `eager_input_streaming` from Anthropic tool
  schemas for Bedrock compatibility.

This keeps secrets out of `/proc/<pid>/environ` on a compromised
worker.

## Design decisions

1. **One file = one FileRecord.** The unit of work is a source file,
   not a finding. Scanner, processor, and revalidator all operate on
   files, so atomic per-file locking and idempotent merges fall out
   naturally.

2. **Append-only analysis history.** Re-running the processor doesn't
   overwrite past findings. It appends a new entry to `analysisHistory`
   and merges new findings (deduped by slug + normalized title) into
   `findings`. You can re-run with a different agent, prompt, or model
   and get a strict improvement instead of a destructive replacement.

3. **Plugin-mediated integrations.** Matchers, notifiers, ownership
   sources, and the remote executor all sit behind plugin contracts.
   The open-source release ships with a generic core; org-specific
   matchers, notifiers, ownership oracles, and people directories slot
   in as external plugins.

4. **Per-batch prompt assembly.** A polyglot repo (Next.js + Django)
   splits into language-specific batches. A Python-only batch doesn't
   get Next.js highlights — keeps the per-batch prompt small and
   focused. Modular prompt: core (severity defs, FP guidance) +
   per-framework highlights + per-slug notes + INFO.md +
   `promptAppend`.

5. **Atomic locking with stale-lock reclaim.** `lockedByRunId` claims
   a file. If the owning run is done/error/missing or the lock is >1h
   old, another run can reclaim it. Survives crashes without
   clobbering concurrent runs.

6. **Quota-aware graceful resume.** Provider-specific prose is matched
   to classify quota exhaustion (Claude: "credit balance too low";
   Codex: "you've hit your usage limit"; Gateway: "insufficient_funds";
   etc.). Throws a typed exception that aborts new batches, cancels
   in-flight ones, finalizes finished work, and surfaces a remediation
   message. Re-running the same command resumes where it stopped.

7. **Refusal tracking.** A post-investigation follow-up turn asks the
   agent to self-report declined content. Baked into `analysisHistory`
   for auditing. No silent skips.

## Where the code lives

| Package | Responsibility |
|---|---|
| `packages/core` | Types, schemas, plugin contracts, config loader (`defineConfig`) |
| `packages/scanner` | Regex matchers + scanning engine + tech detection |
| `packages/processor` | AI agent integration (Claude, Codex), batching, triage, revalidate, prompt assembly |
| `packages/deepsec` | Publishable npm package: bundled CLI + `deepsec/config` sub-export + Vercel Sandbox executor |
| `e2e/` | End-to-end tests against a fixture project |

For deeper code-level context, the live source under `packages/` is
the source of truth — these schemas and prompts change per release.

# Architecture

## Pipeline

```
       scan          process        revalidate          enrich           export
        │              │                │                │                  │    
        ▼              ▼                ▼                ▼                  ▼
  candidates  →   findings    TP/FP/Fixed verdict  →  +committers  →  JSON / md-dir
                                                      +ownership
```

Each stage is a separate CLI subcommand and reads/writes a consistent
on-disk representation. Stages are idempotent: re-running merges new
information rather than overwriting.

## On-disk layout

```
data/<projectId>/
├── project.json              # rootPath, githubUrl (auto-managed)
├── INFO.md                   # repo context injected into AI prompts (manual or agent-written)
├── config.json               # priorityPaths, promptAppend, ignorePaths (optional)
├── files/                    # one JSON per scanned file (FileRecord)
│   └── path/to/file.ts.json
├── runs/                     # one JSON per run (RunMeta)
│   └── 20260429-abcd.json
└── reports/                  # generated reports (markdown + JSON)
```

`data/` is gitignored by default. Each `FileRecord` is the source of truth
for everything deepsec knows about a single source file: candidate
matches, AI findings, analysis history, git committer info, ownership.
Full schemas for every file under `data/` are documented in
[data-layout.md](data-layout.md).

The merge model is additive: every stage adds to the FileRecord. A
re-scan merges new candidates into the existing set; a re-process appends
to `analysisHistory` and merges new findings; revalidation tags existing
findings with verdicts. Nothing is overwritten or deleted.

## Stage details

### scan

- **What it does:** Glob the project root, run regex matchers on every
  matched file, write `candidates` to each FileRecord.
- **Cost:** Free (no AI). ~15s for 2k files.
- **Inputs:** Project root, matcher set (built-ins + plugin contributions).
- **Outputs:** `data/<id>/files/**/*.json` with `candidates` populated and
  `status: "pending"`.

The matcher set is built per-run from the default registry plus any
matchers contributed by active plugins. Plugin matchers can override
built-ins by reusing the same slug.

### process

- **What it does:** Pick batches of pending files, send each batch to the
  configured AI agent backend with the system prompt + INFO.md, parse the
  agent's JSON response into `Finding`s, write them back to each FileRecord.
- **Cost:** $$. The expensive stage.
- **Inputs:** FileRecords with `status: "pending"`, `INFO.md`, the prompt
  template (`packages/processor/src/index.ts:DEFAULT_PROMPT_TEMPLATE`).
- **Outputs:** FileRecord `findings[]` populated, `status: "analyzed"`,
  `analysisHistory[]` appended.

Two agent backends are supported, both routed through Vercel AI Gateway
by default:

| `--agent` | SDK | Default model |
|---|---|---|
| `claude-agent-sdk` (default) | `@anthropic-ai/claude-agent-sdk` | `claude-opus-4-7` |
| `codex` | `@openai/codex-sdk` | `gpt-5.5` |

Same prompt, same JSON output schema. You can mix backends within a
project — re-process a file with a different agent and the second run's
findings get merged with the first.

Concurrency: `--concurrency 5 --batch-size 5` means 5 batches in flight,
5 files per batch = 25 files in the air at peak. The processor claims
files atomically via `lockedByRunId` so multiple workers can run in
parallel without stepping on each other.

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

Read-only stages. Don't modify FileRecords; just shape the data for human
or downstream consumption.

- **export** — flat list of findings as JSON or directory of markdown.
- **report** — per-project markdown summary + JSON.
- **metrics** — cross-project counts and TP rates.

## Plugin architecture

Five extension points, all defined in
[`packages/core/src/plugin.ts`](../packages/core/src/plugin.ts):

- `matchers` — additive
- `notifiers` — additive
- `agents` — additive
- `ownership` — single-slot (last plugin wins)
- `people` — single-slot
- `executor` — single-slot

A plugin registers via `deepsec.config.ts`:

```ts
export default defineConfig({
  plugins: [vercel(), myPlugin()],
});
```

The CLI calls `loadConfig()` before parsing args, builds a `PluginRegistry`
from the active plugins, and stashes it on a module-level singleton
(`getRegistry()`). All internal code consults the registry rather than
hard-coding integrations.

See [docs/plugins.md](plugins.md) for the full plugin authoring guide.

## Design decisions

1. **One file = one FileRecord.** The unit of work is a source file, not
   a finding. Scanner, processor, and revalidator all operate on files,
   so atomic per-file locking and idempotent merges fall out naturally.

2. **Append-only analysis history.** Re-running the processor doesn't
   overwrite past findings. It appends a new entry to `analysisHistory`
   and merges new findings (deduped by slug + title) into `findings`. You
   can re-run with a different agent, prompt, or model and get a strict
   improvement instead of a destructive replacement.

3. **Plugin-mediated integrations.** Matchers, notifiers, ownership
   sources, and the remote executor all sit behind plugin contracts. The
   open-source release ships with a generic core; organization-specific
   matchers, notifiers, ownership oracles, and people directories slot
   in as external plugins.

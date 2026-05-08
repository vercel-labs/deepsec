---
name: deepsec-data-layout
description: Reference for deepsec's on-disk data/ schema — FileRecord, RunMeta, ProjectConfig, Finding, AnalysisEntry, the per-file lifecycle and append-only merge model. Activates when the user wants to read data/<id>/ directly with jq, write a downstream tool, or understand what a stage adds to a record.
---

# deepsec data layout

`data/` is deepsec's on-disk state. Each project owns a subdirectory;
files inside are append-only across runs.

```
data/<projectId>/
├── project.json              # rootPath, githubUrl (auto-managed)
├── INFO.md                   # repo context injected into AI prompts
├── config.json               # priorityPaths, promptAppend, ignorePaths (optional)
├── files/                    # one JSON per scanned source file (FileRecord)
│   └── path/to/source.ts.json
├── runs/                     # one JSON per run (RunMeta)
│   └── 20260429215021-19ac.json
└── reports/                  # generated markdown + JSON reports
```

`data/` is **gitignored by default**. To version it (CI, sharing across
machines), commit it explicitly.

The schemas below are the source of truth for any tool that reads
`data/` directly. They live in `packages/core/src/types.ts`.

## project.json — `ProjectConfig`

Auto-written on first scan; safe to edit by hand.

| Field | Type | Purpose |
|---|---|---|
| `projectId` | `string` | Matches the directory name. |
| `rootPath` | `string` | Absolute path to the codebase. Updated each scan with the most recent `--root`. |
| `createdAt` | `string` (ISO) | Project init time. |
| `githubUrl` | `string?` | Auto-detected from `git remote` when missing. |

## config.json — per-project overrides

Optional. Read by `scan` and the AI agents.

| Field | Type | Purpose |
|---|---|---|
| `priorityPaths` | `string[]` | Path prefixes processed first. |
| `promptAppend` | `string` | Free-form text appended to the system prompt for this project. |
| `ignorePaths` | `string[]` | Glob patterns to skip during scan. |

Overrides equivalent fields on the project declaration in
`deepsec.config.ts` if both are present.

## INFO.md

Free-form markdown injected into the AI prompt for `process`,
`triage`, and `revalidate`. Load-bearing for AI precision — see the
`deepsec-getting-started` skill for the agent prompt that writes a
good one.

## files/<path>.json — `FileRecord`

The core per-file accumulator. Every stage **adds to** this record;
nothing is overwritten. Re-scanning merges new candidates.
Re-processing appends to `analysisHistory`. Revalidation annotates
findings rather than replacing them.

The on-disk path mirrors the source path under `<rootPath>` plus a
`.json` suffix: `src/api/auth.ts` → `files/src/api/auth.ts.json`.

### Top-level fields

| Field | Type | Purpose |
|---|---|---|
| `filePath` | `string` | Path relative to `rootPath`. |
| `projectId` | `string` | The owning project. |
| `candidates` | `CandidateMatch[]` | Regex matcher hits. |
| `lastScannedAt` | `string` (ISO) | Most recent scan timestamp. |
| `lastScannedRunId` | `string` | runId of the scan that last touched this file. |
| `fileHash` | `string` (sha-256) | Source content hash at last scan. |
| `findings` | `Finding[]` | Latest set of AI-produced findings. |
| `analysisHistory` | `AnalysisEntry[]` | Append-only log of every AI investigation. |
| `gitInfo` | `object?` | Git committer info + ownership data, written by `enrich`. |
| `status` | `"pending" \| "processing" \| "analyzed" \| "error"` | Lifecycle state. |
| `lockedByRunId` | `string?` | When non-empty, a run holds this file. Cleared on completion. |

### `CandidateMatch`

| Field | Type | Purpose |
|---|---|---|
| `vulnSlug` | `string` | Matcher slug that fired. |
| `lineNumbers` | `number[]` | 1-indexed source lines. |
| `snippet` | `string` | Short excerpt around the first match. |
| `matchedPattern` | `string` | Human-readable label (the matcher's `label`). |

### `Finding`

| Field | Type | Purpose |
|---|---|---|
| `severity` | `"CRITICAL" \| "HIGH" \| "MEDIUM" \| "HIGH_BUG" \| "BUG" \| "LOW"` | See README. |
| `vulnSlug` | `string` | Matcher slug or `other-<topic>` if no matcher fits. |
| `title` | `string` | One-sentence summary. |
| `description` | `string` | Full explanation. |
| `lineNumbers` | `number[]` | 1-indexed lines. |
| `recommendation` | `string` | Suggested fix. |
| `confidence` | `"high" \| "medium" \| "low"` | Agent's self-rated confidence. |
| `triage` | `Triage?` | Set by `triage`. |
| `revalidation` | `Revalidation?` | Set by `revalidate`. |

### `Triage` (set by `deepsec triage`)

| Field | Type |
|---|---|
| `priority` | `"P0" \| "P1" \| "P2" \| "skip"` |
| `exploitability` | `"trivial" \| "moderate" \| "difficult"` |
| `impact` | `"critical" \| "high" \| "medium" \| "low"` |
| `reasoning` | `string` |
| `triagedAt` | `string` (ISO) |
| `model` | `string` |

### `Revalidation` (set by `deepsec revalidate`)

| Field | Type |
|---|---|
| `verdict` | `"true-positive" \| "false-positive" \| "fixed" \| "uncertain"` |
| `reasoning` | `string` (includes git-history evidence if `fixed`) |
| `adjustedSeverity` | `Severity?` |
| `revalidatedAt` | `string` (ISO) |
| `runId` | `string` |
| `model` | `string` |

### `AnalysisEntry`

One per AI investigation. Append-only — nothing is ever deleted.

| Field | Type |
|---|---|
| `runId` | `string` |
| `investigatedAt` | `string` (ISO) |
| `durationMs` | `number` |
| `durationApiMs` | `number?` |
| `agentType` | `"claude-agent-sdk" \| "codex"` |
| `model` | `string` |
| `modelConfig` | `Record<string, unknown>` |
| `agentSessionId` | `string?` |
| `findingCount` | `number` |
| `numTurns` | `number?` |
| `costUsd` | `number?` |
| `usage` | `{ inputTokens, outputTokens, cacheReadInputTokens, cacheCreationInputTokens }?` |
| `refusal` | `RefusalReport?` |
| `codexStderr` | `string?` (forensic, when an investigation produced 0 output tokens) |
| `reinvestigateMarker` | `number?` (wave marker from `--reinvestigate <N>`) |

### `RefusalReport`

| Field | Type |
|---|---|
| `refused` | `boolean` |
| `reason` | `string?` |
| `skipped` | `Array<{ filePath?: string; reason: string }>?` |
| `raw` | `string?` (trimmed raw model response, for debugging) |

### `gitInfo` (set by `deepsec enrich`)

| Field | Type |
|---|---|
| `recentCommitters` | `Array<{ name, email, date }>` |
| `enrichedAt` | `string` (ISO) |
| `ownership` | `OwnershipData?` (when an ownership plugin is active) |

### `status` lifecycle

```
pending     -- scan finished, awaits AI
   ↓
processing  -- a run is currently investigating (lockedByRunId set)
   ↓
analyzed    -- AnalysisEntry appended; findings updated
```

`error` is set if the agent crashed mid-investigation. Re-running
`process` retries `error` and `pending` files.

## runs/<runId>.json — `RunMeta`

One per `scan` / `process` / `revalidate` invocation. Used for status
reporting (`deepsec status`) and for filtering exports by run.

| Field | Type |
|---|---|
| `runId` | `<YYYYMMDDHHMMSS>-<rand4>` (sortable) |
| `projectId` | `string` |
| `rootPath` | `string` |
| `createdAt` | `string` (ISO) |
| `completedAt` | `string?` (ISO; absent while running) |
| `type` | `"scan" \| "process" \| "revalidate"` |
| `phase` | `"running" \| "done" \| "error"` |
| `scannerConfig` | `{ matcherSlugs }?` (set on scan runs) |
| `processorConfig` | `{ agentType, model, modelConfig }?` (set on process / revalidate runs) |
| `stats` | counters: filesScanned, candidatesFound, findingsCount, totalCostUsd, truePositives, falsePositives, … |

## reports/

Generated by `deepsec report`. One markdown per project plus a JSON
summary. **Re-running `report` overwrites; nothing here is incremental.**

## Reading data/ directly with jq

The append-only model makes a few patterns work well:

**Every TP HIGH+ finding across a project**:
```bash
jq -r '. as $r | $r.findings[]
  | select(.revalidation.verdict=="true-positive")
  | select(.severity=="HIGH" or .severity=="CRITICAL")
  | [$r.filePath, .severity, .title] | @tsv' \
  data/<id>/files/**/*.json
```

**Total spend on a project**:
```bash
jq -s 'map(.analysisHistory[].costUsd // 0) | add' \
  data/<id>/files/**/*.json
```

**Files still pending after a run**:
```bash
jq -r 'select(.status=="pending") | .filePath' \
  data/<id>/files/**/*.json
```

For richer queries, prefer `deepsec export --format json` — it applies
filters consistently with the rest of the CLI.

## Hard rules

- **Don't write to `data/<id>/files/*.json` from outside deepsec.**
  Concurrent runs use `lockedByRunId` for coordination; mutating mid-
  run can corrupt the lock state. Use `deepsec export` to read out;
  use `enrich` / `triage` / `revalidate` to add structured fields.
- **Don't delete `analysisHistory` entries.** They're forensically
  important — model regressions and refusals are diagnosed from this
  trail.
- **Don't depend on the `findings[]` array order.** Findings are
  merged by `(vulnSlug, normalized title)` across re-runs; ordering
  is not stable.

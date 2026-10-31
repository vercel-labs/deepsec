---
title: "Data layout"
description: "The on-disk state deepsec writes for projects, files, runs, findings, and exports."
---

`data/` is deepsec's on-disk state. Each project owns a subdirectory. Scan
and analysis records are append-only across runs; setup evidence is replaced
atomically when its inputs change.

```
data/<projectId>/
├── project.json              # rootPath, githubUrl (auto-managed)
├── INFO.md                   # repo context injected into AI prompts
├── config.json               # priorityPaths, promptAppend, ignorePaths (optional)
├── setup/
│   ├── setup-state.json      # resumable one-shot phase checkpoints
│   └── surface-inventory.json# generated structured ingress inventory
├── files/                    # one JSON per scanned source file (FileRecord)
│   └── path/to/source.ts.json
├── runs/                     # one JSON per run (RunMeta)
│   └── 20260429215021-19ac.json
└── reports/                  # generated markdown + JSON reports
```

The scaffold keeps `INFO.md` and `SETUP.md` trackable, while ignoring
`project.json`, `setup/`, `files/`, `runs/`, and `reports/`. The generated
`setup/` evidence may contain repository paths and platform project IDs, but
never credential values.

The schemas below are the source of truth for any tool that reads
`data/` directly. They live in
[`packages/core/src/types.ts`](https://github.com/vercel-labs/deepsec/blob/main/packages/core/src/types.ts).

## project.json — `ProjectConfig`

Auto-written on first scan; safe to edit by hand.

| Field | Type | Purpose |
|---|---|---|
| `projectId` | `string` | Matches the directory name. |
| `rootPath` | `string` | Absolute path to the codebase. Updated each scan with the most recent `--root`. |
| `createdAt` | `string` (ISO) | Project init time. |
| `githubUrl` | `string?` | `https://github.com/owner/repo/blob/branch` — used for clickable links in exports. Auto-detected from `git remote` if not set. |

## config.json — per-project overrides

Optional. Read by `scan` and the AI agents.

| Field | Type | Purpose |
|---|---|---|
| `priorityPaths` | `string[]` | Path prefixes processed first. |
| `promptAppend` | `string` | Free-form text appended to the system prompt for this project. |
| `ignorePaths` | `string[]` | Glob patterns to skip during scan. |

## INFO.md

Free-form markdown injected into the AI prompt for `process`,
`triage`, and `revalidate`. See
[getting-started](getting-started.md) for the automatic repository-analysis
phase and the manual scaffold fallback.

## `setup/setup-state.json` — SetupState

Versioned coordinator state for `deepsec init` / `deepsec setup`. It records:

- phase status and input/output digests;
- source, INFO, inventory, and generated-matcher fingerprints;
- baseline/final scan IDs and summaries;
- processing run ID;
- non-secret project-link/model-route verification metadata; and
- proposed matcher specs, accepted and rejected slugs, exact rejection
  reasons, and whether an attempt returned no proposal.

Writes use a temporary file plus rename. A phase marked `running` or `error`
is safe to retry. A `complete` checkpoint is reused only when its input digest
matches and required outputs still exist.

## `setup/surface-inventory.json`

The repository-analysis response used by coverage evaluation. Each surface
has a stable ID, kind (`http`, `rpc`, `queue`, `cron`, `cli`, `webhook`,
`agent-tool`, or `other`), exposure, file globs, representative files,
optional anchor regexes, and expected auth primitives. Paths are relative to
the target root and validated before use.

## `files/<path>.json` — FileRecord

The core per-file accumulator. Every stage *adds to* this record;
nothing is overwritten. Re-scanning merges new candidates.
Re-processing appends to `analysisHistory`. Revalidation annotates
findings rather than replacing them.

The on-disk path mirrors the source path under `<rootPath>` plus a
`.json` suffix (`src/api/auth.ts` → `files/src/api/auth.ts.json`).

### Top-level fields

| Field | Type | Purpose |
|---|---|---|
| `filePath` | `string` | Path relative to `rootPath`. |
| `projectId` | `string` | The owning project. |
| `candidates` | `CandidateMatch[]` | Regex matcher hits — see below. |
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
| `matchedPattern` | `string` | Human-readable label of the regex (the matcher's `label`). |

### `Finding`

| Field | Type | Purpose |
|---|---|---|
| `severity` | `"CRITICAL" \| "HIGH" \| "MEDIUM" \| "HIGH_BUG" \| "BUG" \| "LOW"` | See README severity table. |
| `vulnSlug` | `string` | Matcher slug or `other-<topic>` if no matcher fits. |
| `title` | `string` | One-sentence summary. |
| `description` | `string` | Full explanation. |
| `lineNumbers` | `number[]` | 1-indexed lines. |
| `recommendation` | `string` | Suggested fix. |
| `confidence` | `"high" \| "medium" \| "low"` | The agent's self-rated confidence. |
| `triage` | `Triage?` | Set by `triage`. |
| `revalidation` | `Revalidation?` | Set by `revalidate`. |

### `Triage` (set by `deepsec triage`)

| Field | Type | Purpose |
|---|---|---|
| `priority` | `"P0" \| "P1" \| "P2" \| "skip"` | Recommended action bucket. |
| `exploitability` | `"trivial" \| "moderate" \| "difficult"` | Effort to weaponize. |
| `impact` | `"critical" \| "high" \| "medium" \| "low"` | Blast radius if exploited. |
| `reasoning` | `string` | Why this priority. |
| `triagedAt` | `string` (ISO) | Timestamp. |
| `model` | `string` | Model used for triage. |

### `Revalidation` (set by `deepsec revalidate`)

| Field | Type | Purpose |
|---|---|---|
| `verdict` | `"true-positive" \| "false-positive" \| "fixed" \| "uncertain"` | Re-checked verdict. |
| `reasoning` | `string` | Why this verdict. Includes git-history evidence if `fixed`. |
| `adjustedSeverity` | `Severity?` | Set if revalidation re-rates the finding. |
| `revalidatedAt` | `string` (ISO) | Timestamp. |
| `runId` | `string` | runId of the revalidate run. |
| `model` | `string` | Model used. |

### `AnalysisEntry`

One per AI investigation of this file. Append-only — nothing is ever
deleted.

| Field | Type | Purpose |
|---|---|---|
| `runId` | `string` | The producing run. |
| `investigatedAt` | `string` (ISO) | Timestamp. |
| `durationMs` | `number` | Wall-clock total. |
| `durationApiMs` | `number?` | API time only (excludes process orchestration). |
| `agentType` | `string` | `claude-agent-sdk` or `codex`. |
| `model` | `string` | Model identifier. |
| `modelConfig` | `Record<string, unknown>` | Provider-specific settings echoed back. |
| `agentSessionId` | `string?` | The agent's session/thread id, for reproducing or replaying. |
| `findingCount` | `number` | Findings produced in this entry. |
| `numTurns` | `number?` | Conversation turn count. |
| `costUsd` | `number?` | Estimated USD cost. |
| `usage` | `{ inputTokens, outputTokens, cacheReadInputTokens, cacheCreationInputTokens }?` | Token accounting. |
| `refusal` | `RefusalReport?` | See [models](models.md#refusals-are-not-a-large-problem). |
| `codexStderr` | `string?` | Captured codex stderr when an investigation produced 0 output tokens (forensic only). |
| `reinvestigateMarker` | `number?` | Wave marker from `--reinvestigate <N>`. |

### `RefusalReport`

| Field | Type | Purpose |
|---|---|---|
| `refused` | `boolean` | True if the agent skipped or declined any part of the investigation. |
| `reason` | `string?` | Free-form reason if `refused`. |
| `skipped` | `Array<{ filePath?: string; reason: string }>?` | Per-file skip reasons. |
| `raw` | `string?` | Trimmed raw model response to the follow-up question, for debugging. |

### `gitInfo` (set by `deepsec enrich`)

| Field | Type | Purpose |
|---|---|---|
| `recentCommitters` | `Array<{ name, email, date }>` | Top contributors over the file's recent history. |
| `enrichedAt` | `string` (ISO) | Last enrich timestamp. |
| `ownership` | `OwnershipData?` | If an ownership plugin is active, structured ownership/escalation data. |

### `status` lifecycle

```
pending     -- scan finished, awaits AI
   ↓
processing  -- a run is currently investigating (lockedByRunId set)
   ↓
analyzed    -- AnalysisEntry appended; findings updated
```

`error` is set if the agent crashed mid-investigation. Re-running
`process` will retry `error` and `pending` files.

## `runs/<runId>.json` — RunMeta

One per `scan` / `process` / `revalidate` invocation. Used for status
reporting (`deepsec status`) and for filtering exports by run.

| Field | Type | Purpose |
|---|---|---|
| `runId` | `string` | `<YYYYMMDDHHMMSS>-<rand4>`. Sortable. |
| `projectId` | `string` | Owning project. |
| `rootPath` | `string` | Resolved root for the run. |
| `createdAt` | `string` (ISO) | Run start. |
| `completedAt` | `string?` (ISO) | Run end (absent while running). |
| `type` | `"scan" \| "process" \| "revalidate"` | Stage. |
| `phase` | `"running" \| "done" \| "error"` | Terminal status. |
| `scannerConfig` | `{ matcherSlugs }?` | Set on scan runs. |
| `processorConfig` | `{ agentType, model, modelConfig }?` | Set on process / revalidate runs. |
| `stats` | `object` | Counters: filesScanned, candidatesFound, findingsCount, totalCostUsd, truePositives, falsePositives, … |

## reports/

Generated by `deepsec report`. One markdown per project plus a JSON
summary. Re-running `report` overwrites; nothing here is incremental.

## Reading data/ directly

The append-only model means a few patterns work well:

- **Find every TP HIGH+ finding across a project**:
  ```bash
  jq -r '. as $r | $r.findings[] | select(.revalidation.verdict=="true-positive") | select(.severity=="HIGH" or .severity=="CRITICAL") | [$r.filePath, .severity, .title] | @tsv' data/<id>/files/**/*.json
  ```
- **Total spend on a project**:
  ```bash
  jq -s 'map(.analysisHistory[].costUsd // 0) | add' data/<id>/files/**/*.json
  ```
- **Files still pending after a run**:
  ```bash
  jq -r 'select(.status=="pending") | .filePath' data/<id>/files/**/*.json
  ```

For richer queries, prefer `deepsec export --format json` — it applies
filters consistently with the rest of the CLI.

import { z } from "zod";

export const candidateMatchSchema = z.object({
  vulnSlug: z.string(),
  lineNumbers: z.array(z.number()),
  snippet: z.string(),
  matchedPattern: z.string(),
});

export const revalidationSchema = z.object({
  // "accepted-risk" is a manual marker (the agent never produces it): the
  // finding is a real true-positive, but the team has consciously chosen to
  // live with it — see the "accepted risks" section in the project README.
  // Treated like "false-positive" for PR-comment / report-default filtering.
  //
  // "duplicate" means the finding describes the same underlying issue as
  // another finding in the same file. `duplicateOf` points at the primary
  // (canonical) finding by `title`. The primary keeps its real verdict;
  // the processor rejects any DUPE whose `duplicateOf` is missing or
  // points at another DUPE so each group has exactly one non-DUPE.
  verdict: z.enum([
    "true-positive",
    "false-positive",
    "fixed",
    "uncertain",
    "accepted-risk",
    "duplicate",
  ]),
  reasoning: z.string(),
  adjustedSeverity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "HIGH_BUG", "BUG", "LOW"]).optional(),
  duplicateOf: z.string().optional(),
  revalidatedAt: z.string(),
  runId: z.string(),
  model: z.string(),
});

export const findingSchema = z.object({
  // Stable deterministic identity (`finding_<sha256 prefix>`). Optional
  // for records written before the field existed; backfilled on load.
  findingId: z.string().optional(),
  severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "HIGH_BUG", "BUG", "LOW"]),
  vulnSlug: z.string(),
  title: z.string(),
  description: z.string(),
  lineNumbers: z.array(z.number()),
  recommendation: z.string(),
  confidence: z.enum(["high", "medium", "low"]),
  triage: z
    .object({
      priority: z.enum(["P0", "P1", "P2", "skip"]),
      exploitability: z.enum(["trivial", "moderate", "difficult"]),
      impact: z.enum(["critical", "high", "medium", "low"]),
      reasoning: z.string(),
      triagedAt: z.string(),
      model: z.string(),
    })
    .optional(),
  revalidation: revalidationSchema.optional(),
  producedByRunId: z.string().optional(),
});

export const refusalReportSchema = z.object({
  refused: z.boolean(),
  reason: z.string().optional(),
  skipped: z
    .array(
      z.object({
        filePath: z.string().optional(),
        reason: z.string(),
      }),
    )
    .optional(),
  raw: z.string().optional(),
});

export const analysisEntrySchema = z.object({
  runId: z.string(),
  investigatedAt: z.string(),
  durationMs: z.number(),
  durationApiMs: z.number().optional(),
  agentType: z.string(),
  model: z.string(),
  modelConfig: z.record(z.unknown()),
  agentSessionId: z.string().optional(),
  findingCount: z.number(),
  numTurns: z.number().optional(),
  /**
   * "process" (default) = investigation run; "revalidate" = revalidation
   * pass. Optional for backward compat with entries written before the
   * field existed.
   */
  phase: z.enum(["process", "revalidate"]).optional(),
  costUsd: z.number().optional(),
  usage: z
    .object({
      inputTokens: z.number(),
      outputTokens: z.number(),
      cacheReadInputTokens: z.number(),
      cacheCreationInputTokens: z.number(),
    })
    .optional(),
  refusal: refusalReportSchema.optional(),
  /**
   * Tail of codex CLI stderr captured by our wrapper when an investigation
   * produced 0 output tokens (gateway soft-fail / silent failure). Used
   * for forensic debugging; truncated to ~3000 chars.
   */
  codexStderr: z.string().optional(),
  /**
   * The `--reinvestigate <N>` value the run was started with — wave marker
   * used for idempotency: re-running with the same N skips files already
   * carrying this marker for the same agent.
   */
  reinvestigateMarker: z.number().optional(),
});

export const fileRecordSchema = z.object({
  filePath: z.string(),
  projectId: z.string(),
  candidates: z.array(candidateMatchSchema),
  lastScannedAt: z.string(),
  lastScannedRunId: z.string(),
  fileHash: z.string(),
  findings: z.array(findingSchema),
  analysisHistory: z.array(analysisEntrySchema),
  gitInfo: z
    .object({
      recentCommitters: z.array(
        z.object({
          name: z.string(),
          email: z.string(),
          date: z.string(),
        }),
      ),
      enrichedAt: z.string(),
      ownership: z
        .object({
          contributors: z.array(
            z.object({
              email: z.string(),
              name: z.string(),
              github_username: z.string(),
              score: z.number(),
              context: z.string(),
              last_contrib: z.string(),
            }),
          ),
          escalationTeams: z.array(
            z.object({
              name: z.string(),
              slug: z.string(),
              source: z.string(),
              escalation_path_id: z.string(),
              slack_channel_id: z.string().nullable(),
              manager: z.object({
                email: z.string(),
                slack_user_id: z.string(),
              }),
              current_oncall: z.object({
                name: z.string(),
                email: z.string(),
                slack_user_id: z.string(),
                github_username: z.string(),
              }),
            }),
          ),
          approvers: z.array(
            z.object({
              owner: z.string(),
              owner_type: z.string(),
              pattern: z.string().nullable(),
              is_primary: z.boolean(),
              is_direct: z.boolean(),
            }),
          ),
          fetchedAt: z.string(),
        })
        .optional(),
    })
    .optional(),
  status: z.enum(["pending", "processing", "analyzed", "error"]),
  lockedByRunId: z.string().optional(),
  lockedAt: z.string().optional(),
});

/**
 * Compact one-line rendering of a zod error for log messages:
 * `severity: Invalid enum value ...; lineNumbers.0: Expected number ...`.
 */
export function formatSchemaIssues(error: z.ZodError, limit = 5): string {
  const issues = error.issues
    .slice(0, limit)
    .map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`);
  const extra = error.issues.length > limit ? ` (+${error.issues.length - limit} more)` : "";
  return issues.join("; ") + extra;
}

/**
 * The record envelope with findings left unvalidated, so a record whose
 * only defect is inside `findings` can still be salvaged finding-by-finding.
 */
const fileRecordEnvelopeSchema = fileRecordSchema.extend({ findings: z.array(z.unknown()) });

export type FileRecordSalvageResult =
  | {
      ok: true;
      record: z.infer<typeof fileRecordSchema>;
      /** Findings dropped because they individually failed `findingSchema`. */
      droppedFindings: Array<{ index: number; issues: string }>;
    }
  | { ok: false; error: string };

/**
 * Validate an already-JSON-parsed value as a FileRecord, salvaging at
 * finding granularity. Agent output is only field-validated on the write
 * path since findings-validation landed there — records written by older
 * versions (or by a model that slipped a malformed field past a repair
 * pass) still exist on disk. All-or-nothing `fileRecordSchema.parse` made
 * one bad finding silently erase every valid finding in the same file;
 * this keeps the valid ones and reports what was dropped so callers can
 * warn instead of swallowing.
 *
 * `ok: false` means the envelope itself (any field other than the
 * individual findings) is invalid — nothing safe to keep.
 */
export function salvageFileRecord(raw: unknown): FileRecordSalvageResult {
  const strict = fileRecordSchema.safeParse(raw);
  if (strict.success) return { ok: true, record: strict.data, droppedFindings: [] };

  const envelope = fileRecordEnvelopeSchema.safeParse(raw);
  if (!envelope.success) return { ok: false, error: formatSchemaIssues(envelope.error) };

  const findings: z.infer<typeof findingSchema>[] = [];
  const droppedFindings: Array<{ index: number; issues: string }> = [];
  envelope.data.findings.forEach((f, index) => {
    const parsed = findingSchema.safeParse(f);
    if (parsed.success) findings.push(parsed.data);
    else droppedFindings.push({ index, issues: formatSchemaIssues(parsed.error) });
  });
  return { ok: true, record: { ...envelope.data, findings }, droppedFindings };
}

export const runMetaSchema = z.object({
  runId: z.string(),
  projectId: z.string(),
  rootPath: z.string(),
  createdAt: z.string(),
  completedAt: z.string().optional(),
  type: z.enum(["scan", "process", "revalidate"]),
  phase: z.enum(["running", "done", "error"]),
  pid: z.number().optional(),
  hostname: z.string().optional(),
  scannerConfig: z
    .object({
      matcherSlugs: z.array(z.string()),
      mode: z.enum(["full", "files"]).optional(),
      source: z.string().optional(),
      fileCount: z.number().optional(),
    })
    .optional(),
  processorConfig: z
    .object({
      agentType: z.string(),
      model: z.string(),
      modelConfig: z.record(z.unknown()),
      invocationMode: z.enum(["scan", "direct"]).optional(),
      source: z.string().optional(),
    })
    .optional(),
  stats: z.object({
    filesScanned: z.number().optional(),
    candidatesFound: z.number().optional(),
    filesProcessed: z.number().optional(),
    findingsCount: z.number().optional(),
    totalCostUsd: z.number().optional(),
    totalInputTokens: z.number().optional(),
    totalOutputTokens: z.number().optional(),
    totalDurationMs: z.number().optional(),
    findingsRevalidated: z.number().optional(),
    truePositives: z.number().optional(),
    falsePositives: z.number().optional(),
    fixed: z.number().optional(),
    uncertain: z.number().optional(),
    duplicates: z.number().optional(),
  }),
});

export const projectConfigSchema = z.object({
  projectId: z.string(),
  rootPath: z.string(),
  createdAt: z.string(),
  githubUrl: z.string().optional(),
});

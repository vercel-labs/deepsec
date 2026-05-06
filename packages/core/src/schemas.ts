import { z } from "zod";

export const candidateMatchSchema = z.object({
  vulnSlug: z.string(),
  lineNumbers: z.array(z.number()),
  snippet: z.string(),
  matchedPattern: z.string(),
});

export const revalidationSchema = z.object({
  verdict: z.enum(["true-positive", "false-positive", "fixed", "uncertain"]),
  reasoning: z.string(),
  adjustedSeverity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "HIGH_BUG", "BUG", "LOW"]).optional(),
  revalidatedAt: z.string(),
  runId: z.string(),
  model: z.string(),
});

export const findingSchema = z.object({
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
});

export const runMetaSchema = z.object({
  runId: z.string(),
  projectId: z.string(),
  rootPath: z.string(),
  createdAt: z.string(),
  completedAt: z.string().optional(),
  type: z.enum(["scan", "process", "revalidate"]),
  phase: z.enum(["running", "done", "partial", "error"]),
  scannerConfig: z.object({ matcherSlugs: z.array(z.string()) }).optional(),
  processorConfig: z
    .object({
      agentType: z.string(),
      model: z.string(),
      modelConfig: z.record(z.unknown()),
    })
    .optional(),
  stats: z.object({
    filesScanned: z.number().optional(),
    candidatesFound: z.number().optional(),
    filesProcessed: z.number().optional(),
    filesFailed: z.number().optional(),
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
  }),
});

export const projectConfigSchema = z.object({
  projectId: z.string(),
  rootPath: z.string(),
  createdAt: z.string(),
  githubUrl: z.string().optional(),
});

import { z } from "zod";
import { blockerSchema, httpMethodSchema, liveLimitsSchema, liveVerdictSchema } from "./live.js";

// ---------------------------------------------------------------------------
// Live execution contracts — see plans/live-investigations.md (Milestone 1).
//
// These are the typed artifacts of an executed live run: sanitized probe
// observations, assertion outcomes, per-unit results, blockers, and the run
// summary. They are pure data (no network access) so the no-network CLI and
// tests can depend on them; the privileged probe executor that *produces*
// them lives in packages/deepsec.
//
// Load-bearing invariant: evidence carries request/response *metadata* only —
// method, path, query, allowlisted+redacted headers, status, byte counts,
// hashes, timing. Never response bodies, raw cookies, or credential values.
// ---------------------------------------------------------------------------

/**
 * Headers persisted in evidence. An allowlist (not a denylist): the
 * security-header template's assertion inputs plus a small telemetry set.
 * Everything else is dropped before anything is written to disk.
 */
export const EVIDENCE_HEADER_ALLOWLIST: readonly string[] = [
  "content-security-policy",
  "content-type",
  "location",
  "server",
  "set-cookie",
  "strict-transport-security",
  "www-authenticate",
  "x-content-type-options",
  "x-frame-options",
];

/**
 * Request-header names whose values are always replaced with "[redacted]"
 * before an observation leaves the executor, in addition to any configured
 * secret values (matched by exact value, see sanitize in the probe runner).
 */
export const SENSITIVE_REQUEST_HEADERS: readonly string[] = [
  "authorization",
  "cookie",
  "proxy-authorization",
  "x-api-key",
];

export const REDACTED = "[redacted]";

// --- Sanitized probe observation ---

export const probeRequestRecordSchema = z.object({
  method: httpMethodSchema,
  path: z.string(),
  query: z.record(z.string()).default({}),
  /** Allowlisted header names only; sensitive values replaced by REDACTED. */
  headerNames: z.array(z.string()).default([]),
  headerValues: z.record(z.string()).default({}),
  purpose: z.string(),
});
export type ProbeRequestRecord = z.infer<typeof probeRequestRecordSchema>;

export const probeObservationSchema = z.object({
  requestId: z.string(),
  request: probeRequestRecordSchema,
  status: z.number().int(),
  /** EVIDENCE_HEADER_ALLOWLIST names only; secret values replaced by REDACTED. */
  headers: z.record(z.string()),
  bodyBytes: z.number().int().nonnegative(),
  bodyTruncated: z.boolean(),
  /** sha256 of the (capped) body — correlation without retaining content. */
  bodyHash: z.string(),
  timingMs: z.number().nonnegative(),
  /** Redirects are never followed; the Location target is recorded as data. */
  redirect: z
    .object({
      location: z.string(),
      locationOrigin: z.string().optional(),
      locationInScope: z.boolean(),
    })
    .optional(),
});
export type ProbeObservation = z.infer<typeof probeObservationSchema>;

// --- Assertions and unit results ---

export const assertionOutcomeSchema = z.object({
  assertionId: z.string(),
  outcome: z.enum(["pass", "fail", "inconclusive"]),
  /** Deterministic, writer-generated detail. Never raw response text. */
  detail: z.string(),
});
export type AssertionOutcome = z.infer<typeof assertionOutcomeSchema>;

export const liveUnitStatusSchema = z.enum(["completed", "blocked", "skipped-budget", "error"]);
export type LiveUnitStatus = z.infer<typeof liveUnitStatusSchema>;

/** The executed outcome of one plan (one unit of work). */
export const liveUnitResultSchema = z.object({
  planId: z.string(),
  unitRef: z.string(),
  templateId: z.string(),
  route: z.string(),
  status: liveUnitStatusSchema,
  /** Present when the unit reached adjudication; absent for blocked/error. */
  verdict: liveVerdictSchema.optional(),
  assertions: z.array(assertionOutcomeSchema).default([]),
  /** Basename of the evidence artifact under the run's evidence/ dir. */
  evidenceRef: z.string().optional(),
  requestCount: z.number().int().nonnegative(),
  blockedReason: z.string().optional(),
  blocker: blockerSchema.optional(),
  reasoning: z.string(),
  startedAt: z.string(),
  completedAt: z.string(),
});
export type LiveUnitResult = z.infer<typeof liveUnitResultSchema>;

/** One unit's sanitized evidence artifact (append-only, one per unit). */
export const liveEvidenceSchema = z.object({
  version: z.literal(1),
  planId: z.string(),
  unitRef: z.string(),
  templateId: z.string(),
  route: z.string(),
  scopeDigest: z.string(),
  observations: z.array(probeObservationSchema),
  assertions: z.array(assertionOutcomeSchema).default([]),
  verdict: liveVerdictSchema.optional(),
  blockedReason: z.string().optional(),
  startedAt: z.string(),
  completedAt: z.string(),
});
export type LiveEvidence = z.infer<typeof liveEvidenceSchema>;

// --- Run summary ---

export const liveRunSummarySchema = z.object({
  version: z.literal(1),
  runId: z.string(),
  projectId: z.string(),
  targetId: z.string(),
  scopeDigest: z.string(),
  /** True when the loopback no-op approval path was used. */
  loopbackApproval: z.boolean(),
  limits: liveLimitsSchema,
  startedAt: z.string(),
  completedAt: z.string(),
  counts: z.object({
    planned: z.number().int().nonnegative(),
    executed: z.number().int().nonnegative(),
    blocked: z.number().int().nonnegative(),
    skipped: z.number().int().nonnegative(),
    requests: z.number().int().nonnegative(),
  }),
  verdicts: z.record(z.number().int().nonnegative()),
  units: z.array(liveUnitResultSchema),
  blockers: z.array(blockerSchema),
});
export type LiveRunSummary = z.infer<typeof liveRunSummarySchema>;

// --- Audit log events (one JSONL line per event) ---

export const liveAuditEventSchema = z.object({
  ts: z.string(),
  runId: z.string(),
  event: z.enum([
    "run-started",
    "scope-approved",
    "action-proposed",
    "action-rejected",
    "action-executed",
    "unit-completed",
    "blocker-raised",
    "run-completed",
  ]),
  unitRef: z.string().optional(),
  detail: z.record(z.unknown()).default({}),
});
export type LiveAuditEvent = z.infer<typeof liveAuditEventSchema>;

/** Lowercase lookup set for the allowlist. */
export function evidenceHeaderAllowlist(): Set<string> {
  return new Set(EVIDENCE_HEADER_ALLOWLIST);
}

/**
 * Replace every occurrence of a configured secret value in `text` with
 * REDACTED. Values only — the secret list itself is never persisted. Empty
 * secrets are ignored (redacting "" would destroy the text).
 */
export function redactSecretValues(text: string, secrets: readonly string[]): string {
  let out = text;
  for (const secret of secrets) {
    if (secret.length === 0) continue;
    out = out.split(secret).join(REDACTED);
  }
  return out;
}

/** Lowercase lookup set for always-redacted request headers. */
export function sensitiveRequestHeaders(): Set<string> {
  return new Set(SENSITIVE_REQUEST_HEADERS);
}

import { createHash } from "node:crypto";
import { z } from "zod";
import type { Finding, Severity } from "./types.js";

// ---------------------------------------------------------------------------
// Live investigation types — see plans/live-investigations.md.
//
// These contracts describe the runtime phases (`live verify`, `live hunt`)
// that confirm source-derived findings against an authorized deployment and
// discover new findings by probing the source-derived attack surface. This
// module holds the shared schemas (target profiles, scope manifests, digests,
// verdicts) that `packages/deepsec` (CLI / planning) and, later, a privileged
// executor both depend on. Everything here is offline: no network access.
// ---------------------------------------------------------------------------

// --- Severity (reused from types.ts) ---

export const severitySchema = z.enum(["CRITICAL", "HIGH", "MEDIUM", "HIGH_BUG", "BUG", "LOW"]);

/** Lower index = more severe. Used for effective-severity thresholds. */
export const SEVERITY_ORDER: readonly Severity[] = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "HIGH_BUG",
  "BUG",
  "LOW",
];

/** True when `a` is at least as severe as `b` (a ranks above or equal to b). */
export function severityAtLeast(a: Severity, b: Severity): boolean {
  return SEVERITY_ORDER.indexOf(a) <= SEVERITY_ORDER.indexOf(b);
}

/**
 * The severity a finding is treated as for selection: the revalidation-adjusted
 * severity when present, else the recorded severity. Revalidation can downgrade
 * (or upgrade) a finding; live verification targets the *effective* bar.
 */
export function effectiveSeverity(finding: Finding): Severity {
  return finding.revalidation?.adjustedSeverity ?? finding.severity;
}

// --- Provenance ---

/**
 * Where a finding originated. `process` (default) is the static-analysis
 * pipeline; `hunt` is a live-hunt runtime observation. Optional for backward
 * compatibility with findings written before the field existed.
 */
export const findingOriginSchema = z.enum(["process", "hunt"]);
export type FindingOrigin = z.infer<typeof findingOriginSchema>;

// --- Live verdicts ---

/**
 * The conclusion a live investigation reaches about one unit of work. See the
 * verdict definitions in the plan; `blocked` raises a resolvable blocker
 * (Iteration), and `confirmed` is gated on binding confidence + snapshot match.
 */
export const liveVerdictSchema = z.enum([
  "confirmed",
  "contradicted",
  "not-observed",
  "inconclusive",
  "blocked",
  "unsafe-to-test",
]);
export type LiveVerdict = z.infer<typeof liveVerdictSchema>;

/**
 * A hunt finding does not reuse revalidate's true-positive/false-positive
 * verdict — for a runtime observation "false-positive" is overloaded (the
 * behavior may be real but intended, the causal file may be elsewhere, etc.).
 * Only `supported` translates to a displayable true positive.
 */
export const sourceCorroborationSchema = z.enum([
  "supported",
  "contradicted",
  "not-located",
  "uncertain",
]);
export type SourceCorroboration = z.infer<typeof sourceCorroborationSchema>;

// --- Risk classes (expected effects, not HTTP verbs) ---

export const riskClassSchema = z.enum(["passive", "safe-active", "state-changing", "prohibited"]);
export type RiskClass = z.infer<typeof riskClassSchema>;

// --- Binding confidence ---

/** How strongly the deployed artifact is tied to the analyzed source. */
export const bindingConfidenceSchema = z.enum(["attested", "observed", "declared", "none"]);
export type BindingConfidence = z.infer<typeof bindingConfidenceSchema>;

// --- Source snapshot ---

/**
 * What was actually analyzed, matched against the deployment claim. A valid
 * binding against a mismatched snapshot (dirty tree, tree-hash mismatch,
 * uncommitted generated files) is stale/inconclusive, not `confirmed`. The
 * snapshot's content fingerprint gates run validity; it is distinct from the
 * per-finding `sourceFingerprint` that gates skip logic.
 */
export const sourceSnapshotSchema = z.object({
  gitCommit: z.string().optional(),
  gitTree: z.string().optional(),
  dirty: z.boolean(),
  /** Hash over the analyzed files. */
  contentFingerprint: z.string(),
});
export type SourceSnapshot = z.infer<typeof sourceSnapshotSchema>;

// --- Target profile ---

export const httpMethodSchema = z.enum([
  "GET",
  "HEAD",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "OPTIONS",
]);
export type HttpMethod = z.infer<typeof httpMethodSchema>;

export const liveIdentitySchema = z.object({
  /** Opaque handle; the credential value lives in the broker, never here. */
  id: z.string(),
  /** Intended test role, e.g. anonymous | user-a | user-b | admin. */
  role: z.string(),
});
export type LiveIdentity = z.infer<typeof liveIdentitySchema>;

export const liveTargetProfileSchema = z.object({
  targetId: z.string(),
  baseUrl: z.string().url(),
  allowedOrigins: z.array(z.string()).default([]),
  /** Bound for redirect follow-up; the executor never follows automatically. */
  maxRedirects: z.number().int().min(0).default(0),
  requestTimeoutMs: z.number().int().positive().default(10_000),
  identities: z.array(liveIdentitySchema).default([]),
  canaryNamespaces: z.array(z.string()).default([]),
  allowedPathPrefixes: z.array(z.string()).default(["/"]),
  deniedPathPrefixes: z.array(z.string()).default([]),
  allowedMethods: z.array(httpMethodSchema).default(["GET", "HEAD", "OPTIONS"]),
});
export type LiveTargetProfile = z.infer<typeof liveTargetProfileSchema>;

// --- Scope manifest ---

export const liveLimitsSchema = z.object({
  maxRequestsPerUnit: z.number().int().positive().default(20),
  maxRequestsPerMinute: z.number().int().positive().default(30),
  maxResponseBytes: z.number().int().positive().default(1_000_000),
  timeoutMs: z.number().int().positive().default(10_000),
});
export type LiveLimits = z.infer<typeof liveLimitsSchema>;

export const liveTestPlanSchema = z.object({
  id: z.string(),
  templateId: z.string(),
  route: z.string(),
  methods: z.array(httpMethodSchema),
  identityRef: z.string(),
  headers: z.record(z.string()).optional(),
  bodyRef: z.string().optional(),
  assertions: z.array(z.string()),
  riskClass: riskClassSchema,
  limits: liveLimitsSchema,
});
export type LiveTestPlan = z.infer<typeof liveTestPlanSchema>;

export const liveScopeManifestSchema = z.object({
  projectId: z.string(),
  targetId: z.string(),
  baseUrl: z.string().url(),
  allowedOrigins: z.array(z.string()),
  /** Verify: selected finding IDs. */
  selectedFindingIds: z.array(z.string()).default([]),
  /** Hunt: selected (routeId, templateId) pairs. */
  selectedRoutes: z.array(z.object({ routeId: z.string(), templateId: z.string() })).default([]),
  allowedMethods: z.array(httpMethodSchema),
  allowedPathPrefixes: z.array(z.string()),
  identities: z.array(liveIdentitySchema),
  limits: liveLimitsSchema,
  permittedRiskClasses: z.array(riskClassSchema),
  authorizationRef: z.string().optional(),
  approver: z.string().optional(),
  expiresAt: z.string().optional(),
  /** Derived by canonicalization; never set by hand. */
  digest: z.string().optional(),
  plans: z.array(liveTestPlanSchema),
});
export type LiveScopeManifest = z.infer<typeof liveScopeManifestSchema>;

// --- Recon: the source-derived attack surface (live hunt input) ---

/** How confidently the extractor inferred that a route requires authentication. */
export const authExpectationSchema = z.enum(["required", "public", "unknown"]);
export type AuthExpectation = z.infer<typeof authExpectationSchema>;

/** One route discovered by an extractor, with the source evidence that produced it. */
export const routeSpecSchema = z.object({
  /** Stable identity: hash of the defining file + path + methods. */
  routeId: z.string(),
  /** URL path with dynamic segments normalized, e.g. /api/users/[id]. */
  path: z.string(),
  methods: z.array(httpMethodSchema),
  /** The file that defines this route (repo-relative). */
  definingFile: z.string(),
  /** Source-derived auth inference; "unknown" is the honest default. */
  authExpectation: authExpectationSchema,
  /** Per-route fingerprint: hash of defining file content + route identity. */
  sourceFingerprint: z.string(),
});
export type RouteSpec = z.infer<typeof routeSpecSchema>;

/**
 * The attack-surface map produced by `live recon`. Cached by the project-level
 * `surfaceFingerprint`, which is computed over the extractor-relevant inputs
 * (route/handler files, middleware, OpenAPI, routing config) plus the extractor
 * name/version and schema version — so an extractor upgrade or middleware change
 * invalidates the cache rather than silently driving a stale hunt.
 */
export const surfaceMapSchema = z.object({
  version: z.literal(1),
  projectId: z.string(),
  /** Project-level fingerprint over extractor inputs + versions. */
  surfaceFingerprint: z.string(),
  extractor: z.string(),
  extractorVersion: z.string(),
  generatedAt: z.string(),
  routes: z.array(routeSpecSchema),
  /** Coverage: what the extractor could not confidently map. */
  coverage: z.object({
    totalRouteFiles: z.number().int().nonnegative(),
    mappedRoutes: z.number().int().nonnegative(),
    /** Files the extractor saw but could not turn into routes. */
    unmappedFiles: z.array(z.string()).default([]),
  }),
});
export type SurfaceMap = z.infer<typeof surfaceMapSchema>;

/** Per-route fingerprint: defining file content + route identity. */
export function routeSourceFingerprint(definingFileContent: string, routeIdentity: string): string {
  return createHash("sha256")
    .update(definingFileContent)
    .update("\0")
    .update(routeIdentity)
    .digest("hex");
}

/** Stable route identity from its defining file + path + methods. */
export function routeId(definingFile: string, path: string, methods: readonly string[]): string {
  const key = `${definingFile}${path}${[...methods].sort().join(",")}`;
  return `route_${createHash("sha256").update(key).digest("hex").slice(0, 16)}`;
}

// --- Blocker (iteration mode) ---

export const blockerKindSchema = z.enum([
  "auth-required",
  "credential-needed",
  "login-approval",
  "scope-expansion",
  "unsafe-to-test",
]);
export type BlockerKind = z.infer<typeof blockerKindSchema>;

export const blockerSchema = z.object({
  blockerId: z.string(),
  runId: z.string(),
  /** findingId or (routeId, templateId) — the blocked unit. */
  unitRef: z.string(),
  kind: blockerKindSchema,
  /** What the agent was trying to do and why it stopped. */
  summary: z.string(),
  /**
   * The specific guidance/credential/approval being requested. Free text the
   * agent writes to explain its need — shown to the operator verbatim but
   * never parsed into policy. Only an operator's typed, digested approval
   * changes what is permitted.
   */
  requestedAugmentation: z.string(),
});
export type Blocker = z.infer<typeof blockerSchema>;

// --- Canonicalization + digest ---

/**
 * Recursively sort object keys so a digest is stable regardless of key
 * insertion order. Arrays preserve order (order is meaningful for plans).
 */
function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const v = (value as Record<string, unknown>)[key];
      if (v !== undefined) out[key] = canonicalize(v);
    }
    return out;
  }
  return value;
}

/**
 * Compute a stable sha256 digest over a scope manifest, ignoring any existing
 * `digest` field. The same logical manifest always digests identically.
 */
export function digestScopeManifest(scope: LiveScopeManifest): string {
  const { digest: _ignored, ...rest } = scope;
  return createHash("sha256")
    .update(JSON.stringify(canonicalize(rest)))
    .digest("hex");
}

// --- Selection (verify-side, offline) ---

export interface LiveSelectOptions {
  minSeverity?: Severity;
  /** Include findings whose revalidation verdict is `uncertain`. Default true. */
  includeUncertain?: boolean;
  /** Include findings with no revalidation at all. Default false. */
  includeUnrevalidated?: boolean;
  /** Restrict to these finding IDs. */
  findingIds?: string[];
}

/**
 * Choose which findings are eligible for live verification. Pure function over
 * the finding list; deterministic and offline. Default bar: effective severity
 * HIGH or CRITICAL, revalidation true-positive or uncertain, and not
 * duplicate/fixed/false-positive/accepted-risk.
 */
export function selectFindingsForVerify(
  findings: Finding[],
  options: LiveSelectOptions = {},
): Finding[] {
  const min = options.minSeverity ?? "HIGH";
  const includeUncertain = options.includeUncertain ?? true;
  const includeUnrevalidated = options.includeUnrevalidated ?? false;
  const idFilter = options.findingIds ? new Set(options.findingIds) : undefined;

  return findings.filter((f) => {
    if (idFilter && !(f.findingId && idFilter.has(f.findingId))) return false;
    if (!severityAtLeast(effectiveSeverity(f), min)) return false;

    const verdict = f.revalidation?.verdict;
    if (verdict === undefined) return includeUnrevalidated;
    if (verdict === "true-positive") return true;
    if (verdict === "uncertain") return includeUncertain;
    // fixed / false-positive / accepted-risk / duplicate are never eligible.
    return false;
  });
}

import fs from "node:fs";
import path from "node:path";
import {
  type Blocker,
  digestScopeManifest,
  type LiveAuditEvent,
  type LiveEvidence,
  type LiveRunSummary,
  type LiveScopeManifest,
  type LiveTestPlan,
  type LiveUnitResult,
  liveAuditLogPath,
  liveBlockersPath,
  liveEvidenceDir,
  liveRunSummaryPath,
  liveScopeManifestSchema,
} from "@deepsec/core";
import { BudgetExceeded, isLoopbackUrl, PolicyViolation, ProbeRunner } from "./probe.js";
import {
  runSecurityHeadersTemplate,
  SECURITY_HEADERS_TEMPLATE_ID,
} from "./templates/security-headers.js";

// ---------------------------------------------------------------------------
// Live run executor (Milestone 1, loopback only).
//
// Loads an approved scope, verifies the operator's approval digest, runs each
// plan through the policy-gated probe runner, and persists append-only
// sanitized artifacts: evidence/<unit>.json, audit.jsonl, blockers.json,
// run.json under data/<projectId>/live/<runId>/.
// ---------------------------------------------------------------------------

/** Refusal raised before any target traffic; the run never starts. */
export class ScopeRefusal extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ScopeRefusal";
  }
}

export interface ExecuteLiveScopeOptions {
  scope: LiveScopeManifest;
  /** Digest the operator approved (from `digestScopeManifest`). */
  approveDigest?: string;
  runId?: string;
  /** Exact secret values to redact from all recorded metadata. */
  secrets?: readonly string[];
}

export interface ExecuteLiveScopeResult {
  summary: LiveRunSummary;
  runDir: string;
}

/** True when approval is a no-op for this scope (loopback base URL). */
export function isLoopbackScope(scope: LiveScopeManifest): boolean {
  return isLoopbackUrl(scope.baseUrl);
}

/**
 * Validate the approval to execute a scope. Refuses (throws ScopeRefusal)
 * unless the provided digest matches a fresh digestScopeManifest and the
 * scope is unexpired. Loopback targets skip the digest comparison — the
 * approval step is a no-op there by design, keeping the fixture loop one
 * command — but expiry is always enforced.
 */
export function verifyScopeApproval(scope: LiveScopeManifest, approveDigest?: string): string {
  if (scope.expiresAt) {
    const expiry = Date.parse(scope.expiresAt);
    if (Number.isNaN(expiry)) {
      throw new ScopeRefusal(`Scope has an unparseable expiresAt: ${scope.expiresAt}`);
    }
    if (expiry <= Date.now()) {
      throw new ScopeRefusal(`Scope expired at ${scope.expiresAt}; regenerate and re-approve it.`);
    }
  }

  const digest = digestScopeManifest(scope);
  if (isLoopbackScope(scope)) {
    // Loopback no-op approval: a mismatch is tolerated but never silently.
    return digest;
  }
  if (!approveDigest) {
    throw new ScopeRefusal(
      "Refusing to run: no --approve-scope digest provided. " +
        `Recomputed scope digest is ${digest}.`,
    );
  }
  if (approveDigest !== digest) {
    throw new ScopeRefusal(
      "Refusing to run: --approve-scope digest does not match the scope manifest.\n" +
        `  provided:  ${approveDigest}\n  recomputed: ${digest}\n` +
        "  Re-approve the current digest; never edit an approved scope in place.",
    );
  }
  return digest;
}

function appendAudit(logPath: string, event: Omit<LiveAuditEvent, "ts">): void {
  const line = JSON.stringify({ ...event, ts: new Date().toISOString() });
  fs.appendFileSync(logPath, line + "\n");
}

function blockerKindFor(err: PolicyViolation): Blocker["kind"] {
  return err.kind;
}

async function executePlan(
  runner: ProbeRunner,
  plan: LiveTestPlan,
  scopeDigest: string,
  runId: string,
  audit: (event: Omit<LiveAuditEvent, "ts">) => void,
): Promise<{ result: LiveUnitResult; evidence: LiveEvidence }> {
  const startedAt = new Date().toISOString();
  const unitRef = plan.id;
  const base = {
    planId: plan.id,
    unitRef,
    templateId: plan.templateId,
    route: plan.route,
    startedAt,
  };
  const evidenceBase = {
    version: 1 as const,
    planId: plan.id,
    unitRef,
    templateId: plan.templateId,
    route: plan.route,
    scopeDigest,
    startedAt,
  };

  if (plan.templateId !== SECURITY_HEADERS_TEMPLATE_ID) {
    const err = new PolicyViolation(
      "unsafe-to-test",
      `No executor for template "${plan.templateId}" in Milestone 1`,
    );
    audit({
      runId,
      event: "action-rejected",
      unitRef,
      detail: { reason: err.message, kind: err.kind },
    });
    return blockedUnit(base, evidenceBase, err, runId);
  }
  if (plan.riskClass !== "passive") {
    const err = new PolicyViolation(
      "unsafe-to-test",
      `Risk class "${plan.riskClass}" is not executable in Milestone 1 (passive only)`,
    );
    audit({
      runId,
      event: "action-rejected",
      unitRef,
      detail: { reason: err.message, kind: err.kind },
    });
    return blockedUnit(base, evidenceBase, err, runId);
  }

  audit({
    runId,
    event: "action-proposed",
    unitRef,
    detail: { templateId: plan.templateId, route: plan.route, method: "GET" },
  });

  try {
    const outcome = await runSecurityHeadersTemplate(runner, plan);
    for (const obs of outcome.observations) {
      audit({
        runId,
        event: "action-executed",
        unitRef,
        detail: { requestId: obs.requestId, status: obs.status, timingMs: obs.timingMs },
      });
    }
    const completedAt = new Date().toISOString();
    return {
      result: {
        ...base,
        status: "completed",
        verdict: outcome.verdict,
        assertions: outcome.assertions,
        requestCount: outcome.observations.length,
        reasoning: outcome.reasoning,
        completedAt,
      },
      evidence: {
        ...evidenceBase,
        observations: outcome.observations,
        assertions: outcome.assertions,
        verdict: outcome.verdict,
        completedAt,
      },
    };
  } catch (err) {
    if (err instanceof PolicyViolation || err instanceof BudgetExceeded) {
      const violation =
        err instanceof PolicyViolation ? err : new PolicyViolation("scope-expansion", err.message);
      audit({
        runId,
        event: "action-rejected",
        unitRef,
        detail: { reason: violation.message, kind: violation.kind },
      });
      return blockedUnit(base, evidenceBase, violation, runId);
    }
    const completedAt = new Date().toISOString();
    const message = err instanceof Error ? err.message : String(err);
    return {
      result: {
        ...base,
        status: "error",
        assertions: [],
        requestCount: 0,
        reasoning: `Probe failed: ${message}`,
        completedAt,
      },
      evidence: { ...evidenceBase, observations: [], assertions: [], completedAt },
    };
  }
}

function blockedUnit(
  base: {
    planId: string;
    unitRef: string;
    templateId: string;
    route: string;
    startedAt: string;
  },
  evidenceBase: {
    version: 1;
    planId: string;
    unitRef: string;
    templateId: string;
    route: string;
    scopeDigest: string;
    startedAt: string;
  },
  err: PolicyViolation,
  runId: string,
): { result: LiveUnitResult; evidence: LiveEvidence } {
  const completedAt = new Date().toISOString();
  const blocker: Blocker = {
    blockerId: `blocker_${runId}_${base.unitRef}`.replace(/[^a-zA-Z0-9_-]/g, "_"),
    runId,
    unitRef: base.unitRef,
    kind: blockerKindFor(err),
    summary: err.message,
    requestedAugmentation:
      err.kind === "scope-expansion"
        ? "Approve a scope that covers this method/path/origin (new digest)."
        : "Supply the missing prerequisite (credential, approval, or scope).",
  };
  return {
    result: {
      ...base,
      status: "blocked",
      verdict: "blocked",
      assertions: [],
      requestCount: 0,
      blockedReason: err.message,
      blocker,
      reasoning: err.message,
      completedAt,
    },
    evidence: {
      ...evidenceBase,
      observations: [],
      assertions: [],
      verdict: "blocked",
      blockedReason: err.message,
      completedAt,
    },
  };
}

/**
 * Execute an approved scope: policy gate -> probe -> typed assertion ->
 * sanitized evidence, per plan. A blocked unit completes as "blocked" (with
 * a resolvable Blocker), never as failed.
 */
export async function executeLiveScope(
  opts: ExecuteLiveScopeOptions,
): Promise<ExecuteLiveScopeResult> {
  const scope = liveScopeManifestSchema.parse(opts.scope);
  const runId = opts.runId ?? `live-${Date.now().toString(36)}`;
  const scopeDigest = verifyScopeApproval(scope, opts.approveDigest);
  const projectId = scope.projectId;

  const runDir = path.join(liveEvidenceDir(projectId, runId), "..");
  fs.mkdirSync(liveEvidenceDir(projectId, runId), { recursive: true });
  const auditPath = liveAuditLogPath(projectId, runId);
  const audit = (event: Omit<LiveAuditEvent, "ts">) => appendAudit(auditPath, event);

  const loopback = isLoopbackScope(scope);
  audit({
    runId,
    event: "run-started",
    detail: { targetId: scope.targetId, baseUrl: scope.baseUrl, plans: scope.plans.length },
  });
  audit({
    runId,
    event: "scope-approved",
    detail: { digest: scopeDigest, loopbackApproval: loopback },
  });

  const runner = new ProbeRunner({ scope, secrets: opts.secrets });
  const units: LiveUnitResult[] = [];
  const blockers: Blocker[] = [];
  let requests = 0;

  for (const plan of scope.plans) {
    const { result, evidence } = await executePlan(runner, plan, scopeDigest, runId, audit);
    // Persist the sanitized evidence artifact, then link it into the result.
    const evidenceName = `${result.unitRef.replace(/[^a-zA-Z0-9_-]/g, "_")}.json`;
    fs.writeFileSync(
      path.join(liveEvidenceDir(projectId, runId), evidenceName),
      JSON.stringify(evidence, null, 2) + "\n",
    );
    result.evidenceRef = evidenceName;
    requests += result.requestCount;
    if (result.blocker) {
      blockers.push(result.blocker);
      audit({
        runId,
        event: "blocker-raised",
        unitRef: result.unitRef,
        detail: { blockerId: result.blocker.blockerId, kind: result.blocker.kind },
      });
    }
    audit({
      runId,
      event: "unit-completed",
      unitRef: result.unitRef,
      detail: { status: result.status, verdict: result.verdict },
    });
    units.push(result);
  }

  const verdicts: Record<string, number> = {};
  for (const unit of units) {
    if (unit.verdict) verdicts[unit.verdict] = (verdicts[unit.verdict] ?? 0) + 1;
  }

  const summary: LiveRunSummary = {
    version: 1,
    runId,
    projectId,
    targetId: scope.targetId,
    scopeDigest,
    loopbackApproval: loopback,
    limits: scope.limits,
    startedAt: units[0]?.startedAt ?? new Date().toISOString(),
    completedAt: new Date().toISOString(),
    counts: {
      planned: scope.plans.length,
      executed: units.filter((u) => u.status === "completed").length,
      blocked: units.filter((u) => u.status === "blocked").length,
      skipped: units.filter((u) => u.status === "skipped-budget").length,
      requests,
    },
    verdicts,
    units,
    blockers,
  };

  fs.writeFileSync(liveRunSummaryPath(projectId, runId), JSON.stringify(summary, null, 2) + "\n");
  fs.writeFileSync(liveBlockersPath(projectId, runId), JSON.stringify(blockers, null, 2) + "\n");
  audit({
    runId,
    event: "run-completed",
    detail: { ...summary.counts, verdicts },
  });

  return { summary, runDir };
}

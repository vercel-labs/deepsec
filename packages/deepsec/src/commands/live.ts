import fs from "node:fs";
import path from "node:path";
import {
  digestScopeManifest,
  type LiveScopeManifest,
  type LiveTargetProfile,
  type LiveTestPlan,
  liveScopeManifestSchema,
  liveTargetProfileSchema,
  loadAllFileRecords,
  type Severity,
  selectFindingsForVerify,
  targetProfilePath,
} from "@deepsec/core";
import { BOLD, CYAN, DIM, GREEN, RESET, YELLOW } from "../formatters.js";
import { executeLiveScope, ScopeRefusal } from "../live/execute.js";
import { loadSurfaceMap, recon } from "../live/recon.js";
import { SECURITY_HEADERS_TEMPLATE_ID } from "../live/templates/security-headers.js";
import { requireExistingDir } from "../require-dir.js";
import { resolveProjectId } from "../resolve-project-id.js";

/**
 * `deepsec live` — offline planning for the runtime phases. Milestone 0
 * implements planning only: it loads findings, selects verify candidates,
 * builds test plans and a scope manifest, and writes them to disk for review.
 * No network access. Execution (probes, policy engine, credential broker)
 * arrives in later milestones behind `--scope` + `--approve-scope`.
 */

export interface LiveVerifyPlanOptions {
  projectId?: string;
  target?: string;
  planOut?: string;
  scopeOut?: string;
  finding?: string[];
  minSeverity?: string;
  includeUnrevalidated?: boolean;
  // --- Execution (Milestone 1: loopback only) ---
  scope?: string;
  approveScope?: string;
  runId?: string;
}

function readTargetProfile(projectId: string, targetId: string): LiveTargetProfile {
  const p = targetProfilePath(projectId, targetId);
  if (!fs.existsSync(p)) {
    throw new Error(
      `No target profile "${targetId}" for project "${projectId}".\n` +
        `  Expected ${p}. Create it via \`deepsec live setup\` (later milestone) ` +
        `or write a target profile JSON there.`,
    );
  }
  const parsed = liveTargetProfileSchema.safeParse(JSON.parse(fs.readFileSync(p, "utf-8")));
  if (!parsed.success) {
    throw new Error(`Invalid target profile at ${p}: ${parsed.error.message}`);
  }
  return parsed.data;
}

function writeJson(outPath: string, value: unknown): void {
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(value, null, 2) + "\n");
}

/** Build one passive GET plan per selected finding (header/disclosure posture). */
function buildVerifyPlans(findings: ReturnType<typeof selectFindingsForVerify>): LiveTestPlan[] {
  return findings.map((f) => ({
    id: `verify:${f.findingId}`,
    templateId: "verify-passive-observation",
    route: "/",
    methods: ["GET"],
    identityRef: "anonymous",
    assertions: ["observes-finding-behavior"],
    riskClass: "passive",
    limits: {
      maxRequestsPerUnit: 20,
      maxRequestsPerMinute: 30,
      maxResponseBytes: 1_000_000,
      timeoutMs: 10_000,
    },
  }));
}

export async function liveVerifyPlanCommand(opts: LiveVerifyPlanOptions): Promise<void> {
  const projectId = resolveProjectId(opts.projectId);

  if (opts.scope) {
    await liveVerifyExecuteCommand(opts, projectId);
    return;
  }

  if (!opts.planOut && !opts.scopeOut) {
    throw new Error(
      "Nothing to do: pass --plan-out <path> and/or --scope-out <path> to plan offline,\n" +
        "  or --scope <path> [--approve-scope <digest>] to execute an approved scope.",
    );
  }

  const minSeverity = (opts.minSeverity ?? "HIGH") as Severity;
  const records = loadAllFileRecords(projectId);
  const allFindings = records.flatMap((r) => r.findings);
  const selected = selectFindingsForVerify(allFindings, {
    minSeverity,
    includeUncertain: true,
    includeUnrevalidated: opts.includeUnrevalidated ?? false,
    findingIds: opts.finding && opts.finding.length > 0 ? opts.finding : undefined,
  });

  const plans = buildVerifyPlans(selected);

  console.log(
    `${BOLD}Live verify (offline planning)${RESET} for project ${BOLD}${projectId}${RESET}`,
  );
  console.log(
    `  ${DIM}${allFindings.length} finding(s) total, ${RESET}${BOLD}${selected.length}${RESET}${DIM} selected at ≥${minSeverity}${RESET}`,
  );

  // A scope manifest requires a target profile; plans do not.
  let scope: LiveScopeManifest | undefined;
  if (opts.target) {
    const profile = readTargetProfile(projectId, opts.target);
    scope = {
      projectId,
      targetId: profile.targetId,
      baseUrl: profile.baseUrl,
      allowedOrigins: profile.allowedOrigins,
      selectedFindingIds: selected.map((f) => f.findingId ?? ""),
      selectedRoutes: [],
      allowedMethods: profile.allowedMethods,
      allowedPathPrefixes: profile.allowedPathPrefixes,
      identities: profile.identities,
      limits: {
        maxRequestsPerUnit: 20,
        maxRequestsPerMinute: 30,
        maxResponseBytes: 1_000_000,
        timeoutMs: profile.requestTimeoutMs,
      },
      permittedRiskClasses: ["passive"],
      plans,
    };
    scope.digest = digestScopeManifest(scope);
  }

  if (opts.planOut) {
    writeJson(opts.planOut, plans);
    console.log(
      `  ${GREEN}Wrote plans${RESET} ${DIM}${plans.length} test plan(s) →${RESET} ${opts.planOut}`,
    );
  }
  if (opts.scopeOut) {
    if (!scope) {
      throw new Error("--scope-out requires --target <target-id> (a checked-in target profile).");
    }
    writeJson(opts.scopeOut, scope);
    console.log(`  ${GREEN}Wrote scope${RESET} ${DIM}→${RESET} ${opts.scopeOut}`);
    console.log(`  ${DIM}Scope digest:${RESET} ${scope.digest}`);
    console.log(
      `  ${DIM}Approve with:${RESET} ${CYAN}deepsec live verify --scope ${opts.scopeOut} --approve-scope ${scope.digest}${RESET}`,
    );
  }

  console.log(
    `${DIM}Offline planning only — no requests were sent. Execute with --scope <path> --approve-scope <digest>.${RESET}`,
  );
}

// --- live verify: execution path (Milestone 1, loopback only) ---

/**
 * `deepsec live verify --scope <path> [--approve-scope <digest>]` — execute an
 * approved scope manifest. Refuses unless the recomputed digest matches the
 * approval and the scope is unexpired; against loopback base URLs the digest
 * check is a no-op (per plan), so the sample-app loop is one command.
 */
async function liveVerifyExecuteCommand(
  opts: LiveVerifyPlanOptions,
  projectId: string,
): Promise<void> {
  const scopePath = opts.scope!;
  if (!fs.existsSync(scopePath)) {
    throw new Error(`Scope manifest not found: ${scopePath}`);
  }
  const parsed = liveScopeManifestSchema.safeParse(JSON.parse(fs.readFileSync(scopePath, "utf-8")));
  if (!parsed.success) {
    throw new Error(`Invalid scope manifest at ${scopePath}: ${parsed.error.message}`);
  }
  const scope = parsed.data;
  if (scope.projectId !== projectId) {
    throw new Error(
      `Scope is for project "${scope.projectId}", not "${projectId}". ` +
        `Pass --project-id ${scope.projectId} or regenerate the scope.`,
    );
  }

  let result: Awaited<ReturnType<typeof executeLiveScope>>;
  try {
    result = await executeLiveScope({
      scope,
      approveDigest: opts.approveScope,
      runId: opts.runId,
    });
  } catch (err) {
    if (err instanceof ScopeRefusal) {
      throw new Error(`${err.message}`);
    }
    throw err;
  }

  const { summary, runDir } = result;
  console.log(
    `${BOLD}Live verify${RESET} for project ${BOLD}${projectId}${RESET} ` +
      `${DIM}(run ${summary.runId}${summary.loopbackApproval ? ", loopback no-op approval" : ""})${RESET}`,
  );
  console.log(
    `  ${DIM}${summary.counts.planned} plan(s):${RESET} ${BOLD}${summary.counts.executed}${RESET}${DIM} executed,${RESET} ` +
      `${summary.counts.blocked} blocked, ${summary.counts.skipped} skipped, ${summary.counts.requests} request(s)`,
  );
  for (const unit of summary.units) {
    const verdict = unit.verdict ?? unit.status;
    const color =
      unit.verdict === "confirmed" ? YELLOW : unit.status === "blocked" ? YELLOW : GREEN;
    console.log(
      `  ${color}${verdict}${RESET} ${unit.route} ${DIM}(${unit.templateId})${RESET} — ${unit.reasoning}`,
    );
  }
  if (summary.blockers.length > 0) {
    console.log(`  ${YELLOW}${summary.blockers.length} blocker(s) raised:${RESET}`);
    for (const b of summary.blockers) {
      console.log(`    ${DIM}${b.blockerId} [${b.kind}] ${b.summary}${RESET}`);
    }
  }
  console.log(`  ${GREEN}Artifacts${RESET} ${DIM}→${RESET} ${runDir}`);
}

// --- live recon ---

export interface LiveReconOptions {
  projectId?: string;
  root?: string;
  out?: string;
}

/**
 * `deepsec live recon` — extract the source-derived attack surface (offline,
 * no target requests) and cache it by surface fingerprint. Prints mandatory
 * coverage so an incomplete extraction is loud, not silent.
 */
export async function liveReconCommand(opts: LiveReconOptions): Promise<void> {
  const projectId = resolveProjectId(opts.projectId);
  const root = requireExistingDir(opts.root ?? ".", "--root");

  const { map, cachePath, fromCache } = recon(projectId, root);

  console.log(`${BOLD}Live recon${RESET} for project ${BOLD}${projectId}${RESET}`);
  console.log(
    `  ${DIM}${map.coverage.mappedRoutes}/${map.coverage.totalRouteFiles} route file(s) mapped,${RESET} ` +
      `${BOLD}${map.routes.length}${RESET}${DIM} route(s), fingerprint ${map.surfaceFingerprint.slice(0, 12)}…${RESET}` +
      (fromCache ? ` ${DIM}(from cache)${RESET}` : ""),
  );

  // Mandatory coverage reporting: unmapped files are a loud signal, because the
  // hunt premise (source defines scope) weakens when extraction misses routes.
  if (map.coverage.unmappedFiles.length > 0) {
    console.log(
      `  ${YELLOW}⚠ ${map.coverage.unmappedFiles.length} route file(s) could not be mapped:${RESET}`,
    );
    for (const f of map.coverage.unmappedFiles.slice(0, 10)) {
      console.log(`    ${DIM}${f}${RESET}`);
    }
    if (map.coverage.unmappedFiles.length > 10) {
      console.log(`    ${DIM}… and ${map.coverage.unmappedFiles.length - 10} more${RESET}`);
    }
  }

  // Auth-expectation distribution — how much of the surface is honestly unknown.
  const byExpectation = { required: 0, public: 0, unknown: 0 };
  for (const r of map.routes) byExpectation[r.authExpectation]++;
  console.log(
    `  ${DIM}auth:${RESET} ${byExpectation.required} required, ${byExpectation.public} public, ` +
      `${byExpectation.unknown} unknown`,
  );

  const outPath = opts.out ?? cachePath;
  if (opts.out) writeJson(opts.out, map);
  console.log(`  ${GREEN}Surface map${RESET} ${DIM}→${RESET} ${outPath}`);
}

// --- live hunt ---

export interface LiveHuntOptions {
  projectId?: string;
  root?: string;
  target?: string;
  runId?: string;
  approveScope?: string;
}

/**
 * `deepsec live hunt` — the open-ended, source-defined hunt. Loads the surface
 * map (recon), builds one passive security-headers plan per in-scope route,
 * assembles a scope manifest from the target profile, and executes it through
 * the same policy-gated executor as `live verify`. Milestone 1 runs a single
 * passive template against loopback targets; later milestones add identities,
 * more templates, and differential corroboration.
 */
export async function liveHuntCommand(opts: LiveHuntOptions): Promise<void> {
  const projectId = resolveProjectId(opts.projectId);
  if (!opts.target) {
    throw new Error(
      "live hunt requires --target <target-id> (a target profile with the base URL to probe).",
    );
  }
  const root = requireExistingDir(opts.root ?? ".", "--root");
  const profile = readTargetProfile(projectId, opts.target);

  // Source-defined scope: the routes the extractor found, not a hand list.
  const map = loadSurfaceMap(projectId, root);

  // Restrict to routes under the target's allowed path prefixes.
  const inScope = map.routes.filter((r) =>
    profile.allowedPathPrefixes.some((p) => r.path === "/" || r.path.startsWith(p)),
  );

  const plans: LiveTestPlan[] = inScope.map((r) => ({
    id: `hunt:${r.path}:${SECURITY_HEADERS_TEMPLATE_ID}`,
    templateId: SECURITY_HEADERS_TEMPLATE_ID,
    route: r.path,
    methods: ["GET"],
    identityRef: "anonymous",
    assertions: [],
    riskClass: "passive",
    limits: {
      maxRequestsPerUnit: 20,
      maxRequestsPerMinute: 30,
      maxResponseBytes: 1_000_000,
      timeoutMs: profile.requestTimeoutMs,
    },
  }));

  const scope: LiveScopeManifest = {
    projectId,
    targetId: profile.targetId,
    baseUrl: profile.baseUrl,
    allowedOrigins: profile.allowedOrigins,
    selectedFindingIds: [],
    selectedRoutes: inScope.map((r) => ({
      routeId: r.routeId,
      templateId: SECURITY_HEADERS_TEMPLATE_ID,
    })),
    allowedMethods: profile.allowedMethods,
    allowedPathPrefixes: profile.allowedPathPrefixes,
    identities: profile.identities,
    limits: {
      maxRequestsPerUnit: 20,
      maxRequestsPerMinute: 30,
      maxResponseBytes: 1_000_000,
      timeoutMs: profile.requestTimeoutMs,
    },
    permittedRiskClasses: ["passive"],
    plans,
  };
  scope.digest = digestScopeManifest(scope);

  console.log(
    `${BOLD}Live hunt${RESET} for project ${BOLD}${projectId}${RESET} ` +
      `${DIM}(${inScope.length}/${map.routes.length} route(s) in scope, template ${SECURITY_HEADERS_TEMPLATE_ID})${RESET}`,
  );

  let result: Awaited<ReturnType<typeof executeLiveScope>>;
  try {
    result = await executeLiveScope({
      scope,
      approveDigest: opts.approveScope,
      runId: opts.runId,
    });
  } catch (err) {
    if (err instanceof ScopeRefusal) {
      throw new Error(`${err.message}`);
    }
    throw err;
  }

  const { summary, runDir } = result;
  console.log(
    `  ${DIM}run ${summary.runId}:${RESET} ${BOLD}${summary.counts.executed}${RESET}${DIM} executed,${RESET} ` +
      `${summary.counts.blocked} blocked, ${summary.counts.requests} request(s)`,
  );
  for (const unit of summary.units) {
    const verdict = unit.verdict ?? unit.status;
    const color =
      unit.verdict === "confirmed" ? YELLOW : unit.status === "blocked" ? YELLOW : GREEN;
    console.log(
      `  ${color}${verdict}${RESET} ${unit.route} ${DIM}(${unit.templateId})${RESET} — ${unit.reasoning}`,
    );
  }
  console.log(`  ${GREEN}Artifacts${RESET} ${DIM}→${RESET} ${runDir}`);
}

import fs from "node:fs";
import path from "node:path";
import type { FileRecord, Severity } from "@deepsec/core";
import {
  completeRun,
  createRunMeta,
  dataDir,
  defaultConcurrency,
  getRegistry,
  loadAllFileRecords,
  readProjectConfig,
  readRunMeta,
  writeFileRecord,
  writeRunMeta,
} from "@deepsec/core";
import { noiseScore } from "@deepsec/scanner";
import { ClaudeAgentSdkPlugin } from "./agents/claude-agent-sdk.js";
import { CodexAgentSdkPlugin } from "./agents/codex-sdk.js";
import { AgentRegistry } from "./agents/registry.js";
import type {
  AgentPlugin,
  AgentProgress,
  InvestigateOutput,
  RevalidateOutput,
} from "./agents/types.js";
import { batchCandidates } from "./batch.js";
import { enrichFileRecord } from "./enrich.js";

export { ClaudeAgentSdkPlugin } from "./agents/claude-agent-sdk.js";
export { CodexAgentSdkPlugin } from "./agents/codex-sdk.js";
export { AgentRegistry } from "./agents/registry.js";
export type { AgentPlugin, AgentProgress } from "./agents/types.js";
export { batchCandidates } from "./batch.js";
export { enrich } from "./enrich.js";
export { triage } from "./triage.js";

const DEFAULT_PROMPT_TEMPLATE = `You are a world-class security researcher with deep expertise in web application security, authentication systems, and modern JavaScript/TypeScript frameworks. You think like an attacker: you look for subtle logic flaws, not just textbook vulnerabilities. You have a track record of finding bugs that automated tools miss — race conditions, auth bypasses via parameter manipulation, and trust boundary violations.

An automated scanner has identified these files as **candidates** worth investigating. The scanner uses regex and heuristic patterns to cast a wide net — many candidates will be false positives, but some will be real vulnerabilities. Your job is to perform a thorough, open-ended security review. Use the flagged patterns as starting points, then investigate each file for ANY security issue you can find — especially the subtle ones that only an expert would catch.

## Severity Classification

- **CRITICAL**: Remote Code Execution (RCE), authentication bypass allowing full access, SQL injection on sensitive data, unrestricted file upload leading to RCE, SSRF to internal services
- **HIGH**: Cross-Site Scripting (XSS), Server-Side Request Forgery (SSRF), privilege escalation, hardcoded secrets/credentials in source code, insecure deserialization, missing authorization on sensitive operations
- **MEDIUM**: Open redirect, weak cryptographic algorithms, missing rate limiting, information disclosure, insecure direct object references, race conditions, logic bugs in auth/permission checks

## Known Vulnerability Categories

The scanner looks for these patterns, but you should look for ALL of them regardless of what the scanner flagged:

| Slug | Category |
|------|----------|
| auth-bypass | Authentication checks that can be circumvented |
| missing-auth | HTTP endpoints without authentication |
| acl-check | Missing or incorrect RBAC/permission checks |
| xss | Cross-site scripting via innerHTML, dangerouslySetInnerHTML, etc. |
| dangerous-html | Unsafe HTML rendering with user-controlled data |
| rce | Remote code execution via exec, eval, spawn, etc. |
| sql-injection | SQL injection via string interpolation/concatenation |
| ssrf | Server-side request forgery via user-controlled URLs |
| path-traversal | File operations with user-controlled paths |
| secrets-exposure | Hardcoded API keys, tokens, passwords |
| insecure-crypto | Weak hash algorithms, insecure random generation |
| open-redirect | Redirects to user-controlled URLs |
| unsafe-redirect | Redirects bypassing validation functions |
| public-endpoint | Public endpoints (__PUBLIC__ auth) exposing sensitive data |
| service-entry-point | Service handlers that may lack proper auth |
| webhook-handler | Webhook endpoints without signature verification |
| iam-permissions | Misconfigured IAM Action/Resource permissions |
| server-action | Next.js Server Actions without auth checks |
| jwt-handling | JWT signing/verification misconfigurations |
| env-exposure | Secrets leaking to client bundles via NEXT_PUBLIC_ |
| rate-limit-bypass | Sensitive operations without rate limiting |
| lua-header-trust | Trusted request headers without validation (Lua/OpenResty) |
| lua-ngx-exec | Dynamic ngx.exec/ngx.redirect/os.execute in Lua |
| lua-shared-dict-poisoning | Cache poisoning via ngx.shared dict writes from request data |
| lua-crypto-weakness | Weak crypto in Lua (timing-unsafe compare, hardcoded IV, ECB) |
| go-ssrf | Go HTTP requests with string-concatenated URLs |
| go-command-injection | Go exec.Command with dynamic arguments |
| header-strip-bypass | Security header stripping that may be bypassable (case/encoding) |
| cache-key-poisoning | Cache keys including attacker-controlled values |
| secret-env-var | Direct access to secret environment variables |
| cross-tenant-id | User-supplied IDs in DB lookups without ownership check |
| secret-in-fallback | Secret env vars with hardcoded fallback values |
| secret-in-log | Credentials in log statements or error responses |
| expensive-api-abuse | Endpoints calling expensive APIs (LLM, AI, paid services) without abuse protection |
| other-* | Any other vulnerability not listed above (use descriptive suffix) |

## False Positive Guidance

Before classifying an issue, check for mitigations:
- Is the input sanitized or escaped before use? (e.g., parameterized queries, HTML escaping, safeJsonStringify)
- Is there middleware or a framework guard that protects this code path? (e.g., withSchema auth, withAuthentication, CSRF tokens)
- Is the vulnerable pattern only used with trusted/internal data, not user input?
- Does the framework (Next.js, Express, etc.) provide built-in protection?
- For auth checks: does a *backend framework* middleware wrap this handler directly (withSchema, withAuthentication, Express middleware)? If yes, that's a valid mitigation. But Next.js middleware.ts alone is NOT a sufficient mitigation — it's too easy to misconfigure and bypass.
- For redirects: is validNextRedirect() or equivalent called before the redirect?

If fully mitigated, do NOT flag it. Report only genuine, exploitable vulnerabilities.

## JSON.stringify in dangerouslySetInnerHTML / script tags

\`JSON.stringify(data)\` inside \`dangerouslySetInnerHTML\` or inline \`<script>\` tags is an XSS vulnerability. If \`data\` contains \`</script>\`, the browser closes the script tag early and interprets the rest as HTML — enabling arbitrary script injection.

**Example attack:** If data contains \`{"name":"</script><script>alert(1)</script>"}\`, the JSON breaks out of the script block.

**Mitigations to check for:**
- \`safeJsonStringify()\` or similar that escapes \`</\` → \`<\\/\`
- HTML entity encoding of the output
- \`JSON.stringify().replace(/</g, '\\\\u003c')\`

**NOT a mitigation:** Server-side-only data does NOT make this safe — if ANY field in the serialized object can be influenced by user input (database values, query params, URL slugs, usernames), it's exploitable. Trace the data origin carefully.

## Auth Bypass Patterns to Look For

Beyond missing auth, look for **subtle bypasses** in code that appears to have auth:

### Query String & URL Manipulation
- **Parameter pollution**: Can duplicate query params (e.g., \`?teamId=x&teamId=y\`) change behavior or bypass checks?
- **Encoded characters**: Does the app handle URL-encoded, double-encoded, or Unicode-normalized paths correctly? (\`%2F\` vs \`/\`, \`%00\` null bytes)
- **Route param injection**: Can dynamic route segments like \`[teamSlug]\` or \`[...path]\` be manipulated to access other users' data?
- **Search params as auth input**: If middleware reads \`searchParams\` for redirects or tokens, can those be spoofed?
- **Token refresh abuse**: Query params like \`force_refresh_access_token=true\` — are they rate-limited?

### Auth Flow Bypasses
- **OAuth callback manipulation**: State parameter tampering, redirect_uri manipulation, custom URI scheme injection
- **Session/JWT weaknesses**: Missing algorithm pinning, stub sessions when auth not configured, test tokens reachable in prod
- **Middleware bypass**: Routes that escape the middleware matcher pattern or hit before auth middleware runs
- **Next.js middleware is NOT sufficient auth**: Next.js \`middleware.ts\` runs at the edge and can be bypassed (matcher patterns miss routes, direct API calls skip it). Only backend framework middleware that wraps the handler directly (e.g., \`withSchema\`, \`withAuthentication\`, Express middleware chains) counts as proper auth. If a route relies solely on Next.js middleware.ts for auth, flag it.
- **Header injection**: Auth headers like \`X-Forwarded-For\`, \`Authorization\`, custom \`x-*\` tokens — are they validated or trusted blindly?

### Authorization Gaps (has auth, wrong auth)
- **Cross-tenant access**: User-supplied \`teamId\`/\`userId\` used in DB queries instead of the authenticated identity
- **Missing resource-level checks**: Auth confirms "user is logged in" but doesn't verify "user owns this resource"
- **Negated permission checks**: \`!(await auth.can(...))\` with inverted logic
- **Server Actions without auth**: Next.js Server Actions are publicly callable POST endpoints — every one needs explicit auth

## Investigation Process

1. Read each target file fully using the Read tool
2. For flagged patterns AND any other suspicious code, trace data flow: where does input come from? Is it user-controlled?
3. Check for sanitization, validation, or middleware guards by reading imported modules
4. Follow the auth chain: does this endpoint have proper authentication AND authorization?
5. Look at related files (imports, middleware, route definitions, shared utils) for full context
6. Think about logic bugs: race conditions, TOCTOU, state management issues, error handling that leaks info
7. Report findings with high confidence only — but DO report novel issues the scanner didn't flag
8. Skip files that are gitignored, generated, vendored, or not production code. If a file is in dist/, node_modules/, vendor/, generated/, or matches .gitignore, return an empty findings array for it.`;

export function createDefaultAgentRegistry(): AgentRegistry {
  const registry = new AgentRegistry();
  registry.register(new ClaudeAgentSdkPlugin());
  registry.register(new CodexAgentSdkPlugin());
  // Plugins can contribute additional backends via `agents: []` in their
  // DeepsecPlugin export. The shape is validated by AgentRegistry at use.
  for (const a of getRegistry().agents as AgentPlugin[]) {
    registry.register(a);
  }
  return registry;
}

export interface ProcessProgress {
  type: "batch_started" | "batch_complete" | "agent_progress" | "all_complete";
  message: string;
  batchIndex?: number;
  totalBatches?: number;
  agentProgress?: AgentProgress;
}

export async function process(params: {
  projectId: string;
  runId?: string;
  agentType?: string;
  config?: Record<string, unknown>;
  promptTemplate?: string;
  /**
   * `true` — always re-investigate every file regardless of history.
   * `number` — wave marker. Process files that don't yet have a productive
   *   analysis by the current agent tagged with this marker. Re-running
   *   the same N is idempotent (skips already-done files); bump N to
   *   request another pass. Different agents get distinct marker spaces.
   * `false`/undefined — default: only pending/error files.
   */
  reinvestigate?: boolean | number;
  /** Max number of files to process in this run */
  limit?: number;
  /** Number of batches to process concurrently (default: 1) */
  concurrency?: number;
  /** Only process files matching this path prefix */
  filter?: string;
  /** Files per batch (default: 5) */
  batchSize?: number;
  /** Override rootPath from project.json (for sandbox execution) */
  rootPathOverride?: string;
  /** Path to JSON manifest file listing exact file paths to process */
  manifestPath?: string;
  /** Only process files that have at least one candidate slug in this set */
  onlySlugs?: string[];
  /** Skip files whose candidate slugs are ALL in this set (files with any other slug still get processed) */
  skipSlugs?: string[];
  onProgress?: (progress: ProcessProgress) => void;
}): Promise<{ runId: string; analysisCount: number; findingCount: number }> {
  const {
    projectId,
    agentType = "claude-agent-sdk",
    config = {},
    promptTemplate = DEFAULT_PROMPT_TEMPLATE,
    reinvestigate = false,
  } = params;

  // Wrap progress callback so it never crashes the processor
  const emitProgress = (progress: ProcessProgress) => {
    try {
      params.onProgress?.(progress);
    } catch (err) {
      console.error(
        `[deepsec] progress callback error: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  };

  const project = readProjectConfig(projectId);
  const effectiveRootPath = params.rootPathOverride
    ? path.resolve(params.rootPathOverride)
    : project.rootPath;

  if (!fs.existsSync(effectiveRootPath)) {
    const source = params.rootPathOverride ? "--root" : `data/${projectId}/project.json:rootPath`;
    throw new Error(
      `Project root does not exist: ${effectiveRootPath}\n` +
        `  (came from ${source})\n` +
        `  Re-scan with the correct path: deepsec scan --project-id ${projectId} --root <correct-path>`,
    );
  }

  // Load manifest if provided
  let manifestFilePaths: Set<string> | undefined;
  if (params.manifestPath) {
    const raw = JSON.parse(fs.readFileSync(params.manifestPath, "utf-8"));
    if (!Array.isArray(raw)) throw new Error("Manifest must be a JSON array of file paths");
    manifestFilePaths = new Set(raw as string[]);
  }

  // Load project INFO.md if it exists
  const infoPath = path.join(dataDir(projectId), "INFO.md");
  let projectInfo = "";
  try {
    projectInfo = fs.readFileSync(infoPath, "utf-8");
  } catch {
    // No INFO.md — that's fine
  }

  // Load project config.json for prompt customization and priority
  const projectConfigJsonPath = path.join(dataDir(projectId), "config.json");
  let projectConfig: {
    priorityPaths?: string[];
    promptAppend?: string;
  } = {};
  try {
    projectConfig = JSON.parse(fs.readFileSync(projectConfigJsonPath, "utf-8"));
  } catch {
    // No config.json — that's fine
  }

  // Append project-specific prompt if configured
  let effectivePrompt = promptTemplate;
  if (projectConfig.promptAppend) {
    effectivePrompt += "\n" + projectConfig.promptAppend;
  }

  const model = (config.model as string) ?? "claude-opus-4-7";

  // Create or resume run
  let runId: string;
  if (params.runId) {
    // Resume existing run
    runId = params.runId;
    const existing = readRunMeta(projectId, runId);
    if (existing.phase === "done") {
      emitProgress({
        type: "all_complete",
        message: `Run ${runId} already completed`,
      });
      return { runId, analysisCount: 0, findingCount: 0 };
    }
  } else {
    // Create new run
    const meta = createRunMeta({
      projectId,
      rootPath: effectiveRootPath,
      type: "process",
      processorConfig: { agentType, model, modelConfig: config },
    });
    writeRunMeta(meta);
    runId = meta.runId;
  }

  const registry = createDefaultAgentRegistry();
  const maybeAgent = registry.get(agentType);
  if (!maybeAgent) {
    throw new Error(`Unknown agent type: ${agentType}. Available: ${registry.types().join(", ")}`);
  }
  const agent = maybeAgent;

  // Load file records and pick which to process
  const allRecords = loadAllFileRecords(projectId);
  let toProcess: FileRecord[];

  if (typeof reinvestigate === "number") {
    // Idempotent reinvestigate: `--reinvestigate <N>` is a *wave marker*.
    // The first run with a given N tags every productive analysis it
    // produces with `reinvestigateMarker = N`; re-running with the same N
    // (e.g. after some sandboxes failed) skips files that already carry
    // this marker for the same agent. Silent-failure entries don't count
    // since they had 0 output tokens — the agent never actually ran.
    //
    // To request a NEW pass, bump N (21 is "wave 21"). Different agents
    // get separate markers because we filter by agentType.
    toProcess = allRecords.filter((r) => {
      const alreadyDone = (r.analysisHistory ?? []).some((h) => {
        if ((h.usage?.outputTokens ?? 0) <= 0) return false;
        if (h.agentType !== agentType) return false;
        return h.reinvestigateMarker === reinvestigate;
      });
      return !alreadyDone;
    });
  } else if (reinvestigate) {
    toProcess = allRecords;
  } else {
    toProcess = allRecords.filter(
      (r) =>
        r.status === "pending" ||
        r.status === "error" ||
        // Unlock stale locks from crashed runs
        (r.status === "processing" && r.lockedByRunId !== runId),
    );
  }

  // Apply manifest filter (exact file list from sandbox orchestrator)
  if (manifestFilePaths) {
    toProcess = toProcess.filter((r) => manifestFilePaths!.has(r.filePath));
  }

  // Slug filters: --only-slugs and --skip-slugs
  const onlySet =
    params.onlySlugs && params.onlySlugs.length > 0 ? new Set(params.onlySlugs) : undefined;
  const skipSet =
    params.skipSlugs && params.skipSlugs.length > 0 ? new Set(params.skipSlugs) : undefined;
  if (onlySet || skipSet) {
    toProcess = toProcess.filter((r) => {
      const slugs = r.candidates.map((c) => c.vulnSlug);
      if (onlySet && !slugs.some((s) => onlySet.has(s))) return false;
      // Keep the record if any slug is NOT in the skip set — if all are skipped, drop it
      if (skipSet && slugs.length > 0 && slugs.every((s) => skipSet.has(s))) return false;
      return true;
    });
  }

  // Sort: noise tier first (precise > normal > noisy), then priority paths
  toProcess.sort((a, b) => {
    // Primary: noise tier (precise matchers first)
    const aSlugs = a.candidates.map((c) => c.vulnSlug);
    const bSlugs = b.candidates.map((c) => c.vulnSlug);
    const noiseDiff = noiseScore(aSlugs) - noiseScore(bSlugs);
    if (noiseDiff !== 0) return noiseDiff;

    // Secondary: priority paths from config
    if (projectConfig.priorityPaths && projectConfig.priorityPaths.length > 0) {
      const priorities = projectConfig.priorityPaths;
      const aPri = priorities.findIndex((p) => a.filePath.startsWith(p));
      const bPri = priorities.findIndex((p) => b.filePath.startsWith(p));
      const aScore = aPri === -1 ? priorities.length : aPri;
      const bScore = bPri === -1 ? priorities.length : bPri;
      if (aScore !== bScore) return aScore - bScore;
    }

    // Tertiary: more candidate matches = higher priority
    return b.candidates.length - a.candidates.length;
  });

  if (toProcess.length === 0) {
    emitProgress({
      type: "all_complete",
      message: "No files to process",
    });
    completeRun(projectId, runId, "done", { filesProcessed: 0 });
    return { runId, analysisCount: 0, findingCount: 0 };
  }

  // Apply path filter
  if (params.filter) {
    toProcess = toProcess.filter((r) => r.filePath.startsWith(params.filter!));
  }

  // Apply limit
  if (params.limit && toProcess.length > params.limit) {
    toProcess = toProcess.slice(0, params.limit);
  }

  // Lock files for this run
  for (const record of toProcess) {
    record.status = "processing";
    record.lockedByRunId = runId;
    writeFileRecord(record);
  }

  const batches = batchCandidates(toProcess, params.batchSize);
  let totalAnalyses = 0;
  let totalFindings = 0;
  let totalCostUsd = 0;
  let totalInputTokens = 0;
  let totalOutputTokens = 0;
  let totalDurationMs = 0;
  let batchesCompleted = 0;
  let batchesInFlight = 0;
  const concurrency = params.concurrency ?? defaultConcurrency();

  async function processBatch(batch: FileRecord[], i: number) {
    batchesInFlight++;
    emitProgress({
      type: "batch_started",
      message: `Processing batch ${i + 1}/${batches.length} (${batch.length} files, ${batchesInFlight} in flight)`,
      batchIndex: i,
      totalBatches: batches.length,
    });

    try {
      const gen = agent.investigate({
        batch,
        projectRoot: effectiveRootPath,
        promptTemplate: effectivePrompt,
        projectInfo,
        config,
      });

      let result = await gen.next();
      while (!result.done) {
        emitProgress({
          type: "agent_progress",
          message: (result.value as AgentProgress).message,
          batchIndex: i,
          totalBatches: batches.length,
          agentProgress: result.value as AgentProgress,
        });
        result = await gen.next();
      }

      const output = result.value as InvestigateOutput;
      const { results, meta: batchMeta } = output;

      // Accumulate run-level stats
      totalCostUsd += batchMeta.costUsd ?? 0;
      totalInputTokens += batchMeta.usage?.inputTokens ?? 0;
      totalOutputTokens += batchMeta.usage?.outputTokens ?? 0;
      totalDurationMs += batchMeta.durationMs;

      // Update file records with results + metadata.
      //
      // Re-investigation always *merges* — existing findings are preserved
      // and only the agent's net-new findings (signature not already on the
      // file) get appended. Signature: vulnSlug + normalized title
      // (lowercase, trimmed). This tolerates minor wording drift while still
      // suppressing duplicates from re-runs. The first analysis on a file
      // (no prior findings) lands as-is.
      for (const res of results) {
        const record = batch.find((r) => r.filePath === res.filePath);
        if (!record) continue;

        const sig = (slug: string | undefined, title: string | undefined) =>
          `${slug ?? ""}::${(title ?? "").trim().toLowerCase()}`;
        const existing = new Set((record.findings ?? []).map((f) => sig(f.vulnSlug, f.title)));
        const newFindings = res.findings.filter((f) => !existing.has(sig(f.vulnSlug, f.title)));
        record.findings = [...(record.findings ?? []), ...newFindings];
        const findingsForHistoryCount = newFindings.length;

        record.analysisHistory.push({
          runId,
          investigatedAt: new Date().toISOString(),
          durationMs: batchMeta.durationMs,
          durationApiMs: batchMeta.durationApiMs,
          agentType,
          model,
          modelConfig: config,
          agentSessionId: batchMeta.agentSessionId,
          findingCount: findingsForHistoryCount,
          numTurns: batchMeta.numTurns,
          costUsd: batchMeta.costUsd,
          usage: batchMeta.usage,
          refusal: batchMeta.refusal,
          codexStderr: batchMeta.codexStderr,
          reinvestigateMarker: typeof reinvestigate === "number" ? reinvestigate : undefined,
        });
        record.status = "analyzed";
        record.lockedByRunId = undefined;
        try {
          enrichFileRecord(record, effectiveRootPath);
        } catch (e) {
          console.error(
            `[deepsec] enrich failed for ${record.filePath}: ${e instanceof Error ? e.message : e}`,
          );
        }
        writeFileRecord(record);

        totalAnalyses++;
        totalFindings += res.findings.length;
      }

      // Mark any files not in results as error
      for (const record of batch) {
        if (!results.some((r) => r.filePath === record.filePath)) {
          record.status = "error";
          record.lockedByRunId = undefined;
          writeFileRecord(record);
        }
      }

      batchesInFlight--;
      batchesCompleted++;
      emitProgress({
        type: "batch_complete",
        message: `Batch ${i + 1}/${batches.length} complete: ${results.length} analyses, ${results.reduce((s, r) => s + r.findings.length, 0)} findings (${batchesInFlight} in flight, ${batchesCompleted}/${batches.length} done)`,
        batchIndex: i,
        totalBatches: batches.length,
      });
    } catch (err) {
      batchesInFlight--;
      batchesCompleted++;
      for (const record of batch) {
        record.status = "error";
        record.lockedByRunId = undefined;
        writeFileRecord(record);
      }
      emitProgress({
        type: "batch_complete",
        message: `Batch ${i + 1}/${batches.length} failed: ${err instanceof Error ? err.message : String(err)} (${batchesInFlight} in flight, ${batchesCompleted}/${batches.length} done)`,
        batchIndex: i,
        totalBatches: batches.length,
      });
    }
  }

  if (concurrency <= 1) {
    // Sequential
    for (let i = 0; i < batches.length; i++) {
      await processBatch(batches[i], i);
    }
  } else {
    // Concurrent with limited parallelism
    let nextIdx = 0;
    async function worker() {
      while (nextIdx < batches.length) {
        const idx = nextIdx++;
        await processBatch(batches[idx], idx);
      }
    }
    const workers = Array.from({ length: Math.min(concurrency, batches.length) }, () => worker());
    await Promise.all(workers);
  }

  completeRun(projectId, runId, "done", {
    filesProcessed: totalAnalyses,
    findingsCount: totalFindings,
    totalCostUsd,
    totalInputTokens,
    totalOutputTokens,
    totalDurationMs,
  });

  emitProgress({
    type: "all_complete",
    message: `Processing complete: ${totalAnalyses} analyses, ${totalFindings} findings`,
  });

  return { runId, analysisCount: totalAnalyses, findingCount: totalFindings };
}

// --- Revalidation ---

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  HIGH_BUG: 3,
  BUG: 4,
  LOW: 5,
};

export async function revalidate(params: {
  projectId: string;
  runId?: string;
  agentType?: string;
  config?: Record<string, unknown>;
  minSeverity?: Severity;
  force?: boolean;
  limit?: number;
  concurrency?: number;
  batchSize?: number;
  filter?: string;
  /** Override rootPath from project.json (for sandbox execution) */
  rootPathOverride?: string;
  /** Path to JSON manifest file listing exact file paths to revalidate */
  manifestPath?: string;
  /** Only revalidate findings with one of these vulnSlugs */
  onlySlugs?: string[];
  /** Skip findings with any of these vulnSlugs */
  skipSlugs?: string[];
  onProgress?: (progress: ProcessProgress) => void;
}): Promise<{
  runId: string;
  revalidated: number;
  truePositives: number;
  falsePositives: number;
  fixed: number;
  uncertain: number;
}> {
  const {
    projectId,
    agentType = "claude-agent-sdk",
    config = {},
    minSeverity,
    force = false,
  } = params;

  const emitProgress = (progress: ProcessProgress) => {
    try {
      params.onProgress?.(progress);
    } catch (err) {
      console.error(
        `[deepsec] progress callback error: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  };

  const project = readProjectConfig(projectId);
  const effectiveRootPath = params.rootPathOverride
    ? path.resolve(params.rootPathOverride)
    : project.rootPath;

  if (!fs.existsSync(effectiveRootPath)) {
    const source = params.rootPathOverride ? "--root" : `data/${projectId}/project.json:rootPath`;
    throw new Error(
      `Project root does not exist: ${effectiveRootPath}\n` +
        `  (came from ${source})\n` +
        `  Re-scan with the correct path: deepsec scan --project-id ${projectId} --root <correct-path>`,
    );
  }

  // Load manifest if provided
  let manifestFilePaths: Set<string> | undefined;
  if (params.manifestPath) {
    const raw = JSON.parse(fs.readFileSync(params.manifestPath, "utf-8"));
    if (!Array.isArray(raw)) throw new Error("Manifest must be a JSON array of file paths");
    manifestFilePaths = new Set(raw as string[]);
  }

  const infoPath = path.join(dataDir(projectId), "INFO.md");
  let projectInfo = "";
  try {
    projectInfo = fs.readFileSync(infoPath, "utf-8");
  } catch {}

  const model = (config.model as string) ?? "claude-opus-4-7";

  let runId: string;
  if (params.runId) {
    runId = params.runId;
  } else {
    const meta = createRunMeta({
      projectId,
      rootPath: effectiveRootPath,
      type: "revalidate",
      processorConfig: { agentType, model, modelConfig: config },
    });
    writeRunMeta(meta);
    runId = meta.runId;
  }

  const registry = createDefaultAgentRegistry();
  const maybeAgent = registry.get(agentType);
  if (!maybeAgent) {
    throw new Error(`Unknown agent type: ${agentType}`);
  }
  const agent = maybeAgent;

  // Load files that have findings needing revalidation
  const revalOnlySet =
    params.onlySlugs && params.onlySlugs.length > 0 ? new Set(params.onlySlugs) : undefined;
  const revalSkipSet =
    params.skipSlugs && params.skipSlugs.length > 0 ? new Set(params.skipSlugs) : undefined;
  const allRecords = loadAllFileRecords(projectId);
  let toRevalidate = allRecords.filter((r) => {
    if (r.findings.length === 0) return false;
    if (params.filter && !r.filePath.startsWith(params.filter)) return false;

    const unrevalidated = r.findings.filter((f) => {
      if (!force && f.revalidation) return false;
      if (minSeverity && SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[minSeverity]) return false;
      if (revalOnlySet && !revalOnlySet.has(f.vulnSlug)) return false;
      if (revalSkipSet?.has(f.vulnSlug)) return false;
      return true;
    });
    return unrevalidated.length > 0;
  });

  // Apply manifest filter (exact file list from sandbox orchestrator)
  if (manifestFilePaths) {
    toRevalidate = toRevalidate.filter((r) => manifestFilePaths!.has(r.filePath));
  }

  // Sort by severity (CRITICAL first) then noise tier
  toRevalidate.sort((a, b) => {
    const aBest = Math.min(...a.findings.map((f) => SEVERITY_ORDER[f.severity]));
    const bBest = Math.min(...b.findings.map((f) => SEVERITY_ORDER[f.severity]));
    if (aBest !== bBest) return aBest - bBest;
    return (
      noiseScore(a.candidates.map((c) => c.vulnSlug)) -
      noiseScore(b.candidates.map((c) => c.vulnSlug))
    );
  });

  if (params.limit && toRevalidate.length > params.limit) {
    toRevalidate = toRevalidate.slice(0, params.limit);
  }

  if (toRevalidate.length === 0) {
    emitProgress({
      type: "all_complete",
      message: "No findings to revalidate",
    });
    completeRun(projectId, runId, "done", { findingsRevalidated: 0 });
    return {
      runId,
      revalidated: 0,
      truePositives: 0,
      falsePositives: 0,
      fixed: 0,
      uncertain: 0,
    };
  }

  let totalRevalidated = 0;
  let totalTP = 0;
  let totalFP = 0;
  let totalFixed = 0;
  let totalUncertain = 0;
  let totalCostUsd = 0;
  let batchesCompleted = 0;
  let batchesInFlight = 0;
  const concurrency = params.concurrency ?? defaultConcurrency();
  const batchSize = params.batchSize ?? 5;

  const batches = batchCandidates(toRevalidate, batchSize);

  async function revalidateBatch(batch: FileRecord[], idx: number) {
    batchesInFlight++;
    const findingCount = batch.reduce(
      (s, f) => s + f.findings.filter((ff) => (!force ? !ff.revalidation : true)).length,
      0,
    );
    emitProgress({
      type: "batch_started",
      message: `Revalidating batch ${idx + 1}/${batches.length} (${batch.length} files, ${findingCount} findings, ${batchesInFlight} in flight)`,
      batchIndex: idx,
      totalBatches: batches.length,
    });

    try {
      const gen = agent.revalidate({
        batch,
        projectRoot: effectiveRootPath,
        projectInfo,
        config,
        force,
      });

      let result = await gen.next();
      while (!result.done) {
        emitProgress({
          type: "agent_progress",
          message: (result.value as AgentProgress).message,
          batchIndex: idx,
          totalBatches: batches.length,
          agentProgress: result.value as AgentProgress,
        });
        result = await gen.next();
      }

      const output = result.value as RevalidateOutput;
      totalCostUsd += output.meta.costUsd ?? 0;

      // Match verdicts to findings across all files in the batch
      for (const verdict of output.verdicts) {
        const file = batch.find((f) => f.filePath === verdict.filePath);
        if (!file) continue;
        const finding = file.findings.find((f) => f.title === verdict.title);
        if (!finding) continue;
        finding.revalidation = {
          verdict: verdict.verdict,
          reasoning: verdict.reasoning,
          adjustedSeverity: verdict.adjustedSeverity,
          revalidatedAt: new Date().toISOString(),
          runId,
          model,
        };
        if (verdict.adjustedSeverity) {
          finding.severity = verdict.adjustedSeverity;
        }
        totalRevalidated++;
        if (verdict.verdict === "true-positive") totalTP++;
        else if (verdict.verdict === "false-positive") totalFP++;
        else if (verdict.verdict === "fixed") totalFixed++;
        else totalUncertain++;
      }

      for (const file of batch) {
        try {
          enrichFileRecord(file, effectiveRootPath);
        } catch (e) {
          console.error(
            `[deepsec] enrich failed for ${file.filePath}: ${e instanceof Error ? e.message : e}`,
          );
        }
        writeFileRecord(file);
      }

      batchesInFlight--;
      batchesCompleted++;
      emitProgress({
        type: "batch_complete",
        message: `Batch ${idx + 1}/${batches.length}: ${output.verdicts.length} verdicts (${batchesInFlight} in flight, ${batchesCompleted}/${batches.length} done)`,
        batchIndex: idx,
        totalBatches: batches.length,
      });
    } catch (err) {
      batchesInFlight--;
      batchesCompleted++;
      emitProgress({
        type: "batch_complete",
        message: `Batch ${idx + 1}/${batches.length} failed: ${err instanceof Error ? err.message : String(err)} (${batchesInFlight} in flight, ${batchesCompleted}/${batches.length} done)`,
        batchIndex: idx,
        totalBatches: batches.length,
      });
    }
  }

  if (concurrency <= 1) {
    for (let i = 0; i < batches.length; i++) {
      await revalidateBatch(batches[i], i);
    }
  } else {
    let nextIdx = 0;
    async function worker() {
      while (nextIdx < batches.length) {
        const idx = nextIdx++;
        await revalidateBatch(batches[idx], idx);
      }
    }
    await Promise.all(
      Array.from({ length: Math.min(concurrency, batches.length) }, () => worker()),
    );
  }

  completeRun(projectId, runId, "done", {
    findingsRevalidated: totalRevalidated,
    truePositives: totalTP,
    falsePositives: totalFP,
    fixed: totalFixed,
    uncertain: totalUncertain,
    totalCostUsd,
  });

  emitProgress({
    type: "all_complete",
    message: `Revalidation complete: ${totalRevalidated} findings — TP: ${totalTP}, FP: ${totalFP}, Fixed: ${totalFixed}, Uncertain: ${totalUncertain}`,
  });

  return {
    runId,
    revalidated: totalRevalidated,
    truePositives: totalTP,
    falsePositives: totalFP,
    fixed: totalFixed,
    uncertain: totalUncertain,
  };
}

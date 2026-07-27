import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import {
  dataDir,
  type FileRecord,
  type Finding,
  findingSchema,
  formatSchemaIssues,
  type RefusalReport,
} from "@deepsec/core";
import { jsonrepair } from "jsonrepair";
import {
  type ExpectedFinding,
  expectedFindingsForBatch,
  reconcileVerdicts,
  shouldRevalidateFinding,
} from "../reconcile.js";
import type {
  AgentProgress,
  InvestigateResult,
  RevalidateRawResponse,
  RevalidateVerdict,
} from "./types.js";

// --- Retry / backoff -------------------------------------------------------

export const MAX_ATTEMPTS = 3;

/**
 * Out-of-quota / out-of-credits is permanent for the duration of this run —
 * retrying just burns minutes against an empty wallet, and continuing to
 * the next batch fails the same way. We classify these separately from
 * transient rate-limits so the agents can throw a `QuotaExhaustedError` and
 * the processor can stop launching new batches.
 *
 * Provider-specific signatures:
 * - `claude-subscription`     — Claude Pro/Max weekly or 5-hour limit
 * - `anthropic-credits`       — direct Anthropic API: credit balance too low
 * - `openai-quota`            — direct OpenAI API: insufficient_quota / 402
 * - `openai-subscription`     — ChatGPT Plus quota via `codex login`
 * - `gateway-credits`         — Vercel AI Gateway: out of gateway credits
 * - `unknown`                 — bare HTTP 402 we couldn't pin to a source
 */
export type QuotaSource =
  | "claude-subscription"
  | "anthropic-credits"
  | "openai-quota"
  | "openai-subscription"
  | "gateway-credits"
  | "unknown";

/**
 * Optional agent hint passed by the per-plugin caller. The same prose
 * ("usage limit") appears in both the Claude and codex binaries, but a
 * caller in `claude-agent-sdk.ts` only ever sees Claude/Anthropic errors,
 * and a caller in `codex-sdk.ts` only ever sees codex/OpenAI errors. The
 * hint resolves the prose-only ambiguity without us trying to fingerprint
 * the source from text alone.
 */
export type QuotaAgentHint = "claude" | "codex";

/**
 * Classify an error message as quota-exhausted, returning the most
 * specific source we can identify, or `undefined` if the message is not
 * a quota error.
 *
 * Patterns below were extracted from the actual platform binaries via
 * `strings`:
 *   - Claude: `@anthropic-ai/claude-agent-sdk-darwin-arm64/claude`
 *   - Codex:  `@openai/codex/vendor/.../bin/codex`
 * plus the well-known stable strings from the upstream HTTP error
 * envelopes (Anthropic `billing_error`, OpenAI `insufficient_quota` /
 * "You exceeded your current quota") which don't appear in the bundled
 * binaries because the binaries just relay them.
 *
 * Matching is intentionally loose — false-positives degrade to a
 * generic but accurate stop-and-direct-to-AI-Gateway message; misses
 * fall through to the existing fail-loud retry logic. Loose > strict.
 */
export function classifyQuotaError(msg: string, hint?: QuotaAgentHint): QuotaSource | undefined {
  if (!msg) return undefined;
  const m = msg.toLowerCase();

  // --- Vercel AI Gateway (matched first; the gateway forwards provider
  // bodies, so a gateway-credits error can incidentally contain provider
  // prose like "Claude" or "OpenAI" — we want gateway attribution to win).
  //
  // Strings extracted from the gateway source itself
  // (vercel/ai-gateway/lib/gateway/check-billing.ts and friends):
  //   - HTTP 402, `error.type: "insufficient_funds"`,
  //     prose: "Insufficient funds. Please add credits to your account…"
  //   - HTTP 403, `error.type: "customer_verification_required"`,
  //     prose: "AI Gateway requires a valid credit card on file…"
  //   - HTTP 429, `error.type: "quota_for_entity_exceeded"`,
  //     prose: 'Quota limit exceeded for "<id>". Current spend: $X, limit: $Y'
  //   - HTTP 429, `error.type: "rate_limit_exceeded"` for video tier limits.
  // The gateway WRAPS upstream provider errors rather than passing them
  // through; client-facing bodies always use the canonical gateway types.
  if (
    /\binsufficient_funds\b/.test(m) ||
    /\bcustomer_verification_required\b/.test(m) ||
    /\bquota_for_entity_exceeded\b/.test(m) ||
    /\binsufficient funds\.?\s+please add credits/.test(m) ||
    /ai gateway requires a valid credit card/.test(m) ||
    // Prose form of `quota_for_entity_exceeded` from check-quota-entity.ts:
    //   `Quota limit exceeded for "<id>". Current spend: $X, limit: $Y.`
    /\bquota limit exceeded for\b/.test(m) ||
    /ai[_ -]?gateway[^.]*?(insufficient[_ ]?credits?|credit balance|out of credits|payment required)/.test(
      m,
    ) ||
    /ai[_ -]?gateway.*\b402\b/.test(m) ||
    // Plain "insufficient credits" without provider attribution typically
    // comes from the gateway; direct providers say "credit balance" or
    // "insufficient_quota" instead.
    /\binsufficient[_ ]credits?\b/.test(m)
  ) {
    return "gateway-credits";
  }

  // --- Anthropic (Claude binary + direct API)
  // Extracted strings from the Claude binary: "Credit balance is too low",
  // "Credit balance too low" (no "is"), "credit balance", and the
  // structured tags `billing_error` / `out_of_credits` / `credit_balance_low`
  // that surface in error envelopes. Match all variants.
  if (
    /credit balance (is )?too low/.test(m) ||
    /\bcredit_balance_low\b/.test(m) ||
    /\bout_of_credits\b/.test(m) ||
    /\bbilling_error\b/.test(m) ||
    // Loose net for prose like "low credit balance" / "insufficient
    // balance" near a Claude/Anthropic mention.
    /(claude|anthropic|claude\.com)[^.]{0,80}\b(low|insufficient)\b[^.]{0,40}\bbalance\b/.test(m) ||
    // The Claude binary also emits `platform.claude.com/settings/billing`
    // alongside the credit message — a hard correlation.
    /platform\.claude\.com\/settings\/billing/.test(m)
  ) {
    return "anthropic-credits";
  }

  // --- Codex / ChatGPT subscription
  // The dominant codex-binary phrase is "You've hit your usage limit"
  // (with several follow-on suffixes pointing at chatgpt.com/explore/plus
  // or chatgpt.com/codex/settings/usage). Internal tags include
  // `workspace_owner_credits_depleted`, `workspace_member_credits_depleted`,
  // `workspace_owner_usage_limit_reached`, `workspace_member_usage_limit_reached`,
  // `usage_limit_exceeded`, `usage_limit_reached`, `usageLimitExceeded`.
  if (
    /you'?ve hit your usage limit/.test(m) ||
    /chatgpt\.com\/(explore\/plus|codex\/settings\/usage)/.test(m) ||
    /workspace_(owner|member)_credits_depleted/.test(m) ||
    /workspace_(owner|member)_usage_limit_reached/.test(m) ||
    /\busagelimitexceeded\b/.test(m) ||
    /\busage_limit_(exceeded|reached)\b/.test(m) ||
    // Plus/Pro upgrade prose.
    /upgrade to plus to continue/.test(m) ||
    /\bchatgpt\s+(plus|pro)\b.*\b(quota|limit)\b/.test(m) ||
    /\bplan limit reached\b/.test(m)
  ) {
    return "openai-subscription";
  }

  // --- Direct OpenAI API quota (insufficient_quota / "exceeded your
  // current quota"). These don't appear in the codex binary because the
  // binary relays whatever the OpenAI API HTTP response says; both are
  // documented stable error codes / phrases from OpenAI.
  if (
    /\binsufficient_quota\b/.test(m) ||
    /\byou exceeded your current quota\b/.test(m) ||
    /\bquota exceeded\b.*\bopenai\b/.test(m) ||
    /\bopenai\b.*\bquota exceeded\b/.test(m)
  ) {
    return "openai-quota";
  }

  // --- Generic "usage limit" / "weekly limit" / "monthly limit" prose
  // appears in BOTH binaries. The agent hint disambiguates the source;
  // without a hint we still want to bail (it's still a quota stop), so
  // we attribute to subscription on whichever side the hint points at,
  // or `unknown` if no hint is available.
  if (
    /\b(weekly|monthly|hourly|5[ -]?hour) limit\b/.test(m) ||
    /\bextra usage limit\b/.test(m) ||
    /\busage limit\b/.test(m)
  ) {
    if (hint === "codex") return "openai-subscription";
    if (hint === "claude") return "claude-subscription";
    // No hint — still a real quota stop; classify generically so the run
    // halts and the CLI shows the gateway-aware fallback message.
    return "unknown";
  }

  // --- Bare HTTP 402 anywhere — payment required, definitely not
  // transient. Falls through to "unknown" so we still bail.
  if (/\b402\b/.test(m) && /payment required|insufficient/.test(m)) {
    return "unknown";
  }

  return undefined;
}

/**
 * Thrown by an agent plugin when the upstream credential is out of
 * quota/credits. The processor catches this, aborts the shared
 * AbortController so in-flight batches stop, and prevents new batches
 * from launching — retrying is pointless when every batch is going to hit
 * the same wall.
 */
export class QuotaExhaustedError extends Error {
  readonly source: QuotaSource;
  readonly rawMessage: string;

  constructor(source: QuotaSource, rawMessage: string) {
    super(`Quota exhausted (${source}): ${rawMessage.slice(0, 300)}`);
    this.name = "QuotaExhaustedError";
    this.source = source;
    this.rawMessage = rawMessage;
  }
}

const CODEX_VENDOR_BINARY_RE =
  /@openai[\\/]codex[\\/]vendor[\\/][\s\S]*?[\\/]codex[\\/]codex(?:\.exe)?/i;

function extractMissingCodexBinaryPath(msg: string): string | undefined {
  const spawnMatch = msg.match(
    /\bspawn\s+(.+?@openai[\\/]codex[\\/]vendor[\\/].+?[\\/]codex[\\/]codex(?:\.exe)?)\s+(?:ENOENT|$)/i,
  );
  if (spawnMatch?.[1]) return spawnMatch[1].trim();

  const pathMatch = msg.match(
    /((?:[A-Za-z]:)?[^"'`\n\r]*?@openai[\\/]codex[\\/]vendor[\\/][^"'`\n\r]*?[\\/]codex[\\/]codex(?:\.exe)?)/i,
  );
  return pathMatch?.[1]?.trim();
}

/**
 * Detect the local failure mode where the vendored @openai/codex executable
 * is gone by the time the SDK tries to spawn it. macOS Gatekeeper/XProtect
 * can kill the binary first (SIGKILL) and quarantine/remove it, but SIGKILL
 * alone is not enough to classify this: we require the vendored binary path
 * plus ENOENT/no-such-file so ordinary process kills stay in the existing
 * retry/error path.
 */
export function isMissingBinaryError(msg: string): boolean {
  if (!msg) return false;
  const hasMissingFileSignature =
    /\bENOENT\b/i.test(msg) || /no such file or directory/i.test(msg);
  return hasMissingFileSignature && CODEX_VENDOR_BINARY_RE.test(msg);
}

export function formatMissingCodexBinaryError(msg: string): string {
  const binaryPath = extractMissingCodexBinaryPath(msg);
  const missingLine = binaryPath ? `\n\nMissing binary: ${binaryPath}` : "";
  const rawLine = msg ? `\n\nOriginal error: ${msg.slice(0, 1000)}` : "";

  return (
    `Codex could not start because the bundled @openai/codex executable is missing or no longer spawnable.` +
    missingLine +
    `\n\nOn macOS, Gatekeeper may have killed or quarantined the vendored Codex binary. ` +
    `That often appears first as "Codex Exec exited with signal SIGKILL", then the next spawn fails with ENOENT.` +
    `\n\nTo fix it, reinstall dependencies so @openai/codex restores the vendored binary. ` +
    `If you trust the installed package, you can also clear the macOS quarantine attribute from the restored package or binary with: ` +
    `xattr -dr com.apple.quarantine <path-to-node_modules/@openai/codex>` +
    rawLine
  );
}

/**
 * Vercel AI Gateway endpoints — duplicated from preflight.ts on purpose:
 * processor doesn't depend on the deepsec CLI package. Keep these in sync
 * with the constants in `packages/deepsec/src/preflight.ts`.
 */
const GATEWAY_ANTHROPIC_BASE_URL = "https://ai-gateway.vercel.sh";
const GATEWAY_OPENAI_BASE_URL = "https://ai-gateway.vercel.sh/v1";

/**
 * Best-effort detection of whether the orchestrator is currently routing
 * through Vercel AI Gateway. Used to tailor the quota-exhausted remediation
 * message — we never tell a user already on the gateway to "switch to AI
 * Gateway."
 *
 * Triggers if any of:
 *   - `AI_GATEWAY_API_KEY` is set (the user-facing var that
 *     `applyAiGatewayDefaults` expands into the per-provider tokens)
 *   - `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` point at the gateway hosts
 */
export function isUsingAiGateway(): boolean {
  if (process.env.AI_GATEWAY_API_KEY) return true;
  const a = process.env.ANTHROPIC_BASE_URL?.replace(/\/$/, "");
  const o = process.env.OPENAI_BASE_URL?.replace(/\/$/, "");
  if (a === GATEWAY_ANTHROPIC_BASE_URL) return true;
  if (o === GATEWAY_OPENAI_BASE_URL) return true;
  return false;
}

/**
 * Transient = worth retrying. Quota errors are NOT transient even though
 * many of them surface with status 429 — the gateway/upstream re-emits the
 * same body on every retry, so we'd just burn our backoff budget.
 *
 * Callers should consult `classifyQuotaError` *first* and short-circuit
 * with a `QuotaExhaustedError`; this function then handles whatever's left.
 * As a defense-in-depth, we also early-return false when the message
 * classifies as quota — covers any caller that forgot to check.
 */
export function isTransientError(msg: string): boolean {
  if (classifyQuotaError(msg)) return false;
  return /\b(5\d\d|429|eager_input_streaming|temporarily unavailable|timeout|ETIMEDOUT|ECONNRESET|overloaded|rate[_ -]?limit)\b/i.test(
    msg,
  );
}

export async function backoff(attempt: number): Promise<void> {
  const ms = 2000 * 2 ** (attempt - 1) + Math.random() * 1000;
  await new Promise((r) => setTimeout(r, ms));
}

// --- Refusal follow-up -----------------------------------------------------

export const REFUSAL_FOLLOWUP_PROMPT = `Before we wrap up, I want to check on one thing.

Looking back at the investigation you just completed: was there anything you declined to fully analyze, refused to look at, or skipped because the content or the task made you uncomfortable or felt out of scope?

Be candid — this is for internal QA of the scanner. Partial analysis is fine to report here. A "no" is also a totally valid answer if you investigated everything requested.

Reply with ONLY a JSON object, no prose before or after:

\`\`\`json
{
  "refused": true | false,
  "reason": "short overall explanation, or null",
  "skipped": [
    { "filePath": "relative/path.ts", "reason": "why you didn't fully analyze this" }
  ]
}
\`\`\`

If you analyzed everything normally, return \`{"refused": false, "skipped": []}\`.`;

export function parseRefusalReport(raw: string): RefusalReport | undefined {
  if (!raw) return undefined;

  const jsonMatch = raw.match(/```json\s*([\s\S]*?)```/);
  const jsonStr = jsonMatch ? jsonMatch[1].trim() : raw.trim();
  try {
    const parsed = JSON.parse(jsonStr) as {
      refused?: boolean;
      reason?: string | null;
      skipped?: Array<{ filePath?: string; reason?: string }>;
    };
    return {
      refused: Boolean(parsed.refused),
      reason: parsed.reason ?? undefined,
      skipped: (parsed.skipped ?? [])
        .filter((s) => s?.reason)
        .map((s) => ({ filePath: s.filePath, reason: s.reason! })),
      raw: raw.slice(0, 2000),
    };
  } catch {
    const lower = raw.toLowerCase();
    const looksRefused =
      /\b(i (can't|cannot|won't|will not|am unable)|refus|decline|not comfortable)\b/.test(lower);
    return {
      refused: looksRefused,
      reason: looksRefused ? "heuristic match on follow-up text" : undefined,
      raw: raw.slice(0, 2000),
    };
  }
}

// --- Investigation prompt --------------------------------------------------

export function buildInvestigatePrompt(params: {
  promptTemplate: string;
  projectInfo: string;
  batch: FileRecord[];
}): string {
  const { promptTemplate, projectInfo, batch } = params;

  const fileList = batch
    .map((r) => {
      // Direct-invocation runs (e.g. `process --diff`) can include files
      // the scanner saw but didn't flag. Render those as a holistic-review
      // hint so the agent doesn't waste turns asking "what's the
      // candidate?" when there isn't one.
      if (r.candidates.length === 0) {
        return `- **${r.filePath}** (no scanner hits — full holistic review)`;
      }
      const matchDetails = r.candidates
        .map((m) => {
          const lines = m.lineNumbers.join(", ");
          return `    - [${m.vulnSlug}] L${lines}: ${m.matchedPattern}`;
        })
        .join("\n");
      return `- **${r.filePath}**\n${matchDetails}`;
    })
    .join("\n");

  // Composition note: when called from the modular `assemblePrompt`
  // pipeline, the system-prompt half (intro, severity, FP guidance,
  // tech highlights, slug notes, INFO.md) already lives in
  // `promptTemplate`. We just append the per-batch concrete list +
  // procedural steps + output spec — no need to repeat the "scanner
  // casts a wide net" intro here.
  //
  // `projectInfo` is only emitted when the caller passes it explicitly.
  // The processor's modular path passes `""` because INFO.md is already
  // in the assembled prompt; custom-template callers (--prompt-template)
  // pass the loaded INFO.md so it still reaches the model.
  const projectInfoBlock = projectInfo ? `## Project Context\n\n${projectInfo}\n\n` : "";

  return `${promptTemplate}

${projectInfoBlock}## Target Files

${fileList}

## Investigation Instructions

For each file:
1. **Read the file fully** using the Read tool
2. **Trace data flows** — where does input come from? Is it user-controlled?
3. **Follow imports** — read related files (middleware, utils, shared libs) to understand the full picture
4. **Check for mitigations** — is there sanitization, validation, auth middleware, or framework protection?
5. **Think broadly** — look for issues beyond what the scanner flagged. The scanner only finds surface patterns; you should reason about logic bugs, race conditions, missing checks, etc.

## Output Format

After your investigation, output a JSON block with your findings for EACH file. Use this exact format:

\`\`\`json
[
  {
    "filePath": "relative/path/to/file.ts",
    "findings": [
      {
        "severity": "CRITICAL|HIGH|MEDIUM|HIGH_BUG|BUG",
        "vulnSlug": "the-vuln-slug-or-other",
        "title": "Brief title of the issue",
        "description": "Detailed description of the vulnerability, the attack scenario, and evidence from the code",
        "lineNumbers": [10, 15],
        "recommendation": "How to fix this vulnerability",
        "confidence": "high|medium|low"
      }
    ]
  }
]
\`\`\`

**Severity levels:**
- **CRITICAL / HIGH / MEDIUM** — security vulnerabilities (exploitable by an attacker)
- **HIGH_BUG** — major non-security bugs that could cause data loss, corruption, outages, or seriously broken behavior
- **BUG** — notable non-security bugs (logic errors, race conditions, resource leaks) that don't rise to HIGH_BUG

**vulnSlug** can be any of the known categories OR a custom slug for issues not covered by the scanner. Use \`"other"\` as the slug prefix for novel findings (e.g., \`"other-race-condition"\`, \`"other-logic-bug"\`, \`"other-info-disclosure"\`).

If a file has no real vulnerabilities after thorough investigation, include it with an empty findings array.`;
}

/**
 * Persist the raw agent output that failed to parse as JSON to a debug
 * location. Lives at `data/<projectId>/debug/parse-error-<phase>-<ts>.txt`
 * so a sandbox run picks it up in the normal results tarball — the
 * sandbox download allowlist explicitly accepts `debug/*.txt`.
 *
 * Best-effort: never throws (callers are already on the error path and
 * we don't want to mask the original JSON-parse error with a disk-full
 * EIO). Returns the path written to, or undefined on failure.
 */
export function writeParseFailureDebug(params: {
  projectId?: string;
  phase: "investigate" | "revalidate";
  agentType: string;
  resultText: string;
  error: unknown;
  batch?: FileRecord[];
}): string | undefined {
  const { projectId, phase, agentType, resultText, error, batch } = params;
  if (!projectId) return undefined;
  try {
    const dir = path.join(dataDir(projectId), "debug");
    fs.mkdirSync(dir, { recursive: true });
    const ts = new Date().toISOString().replace(/[:.]/g, "-");
    const file = path.join(dir, `parse-error-${phase}-${ts}.txt`);
    const errMsg = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
    const filesList = batch?.map((b) => `  - ${b.filePath}`).join("\n") ?? "  (none)";
    const header =
      `# deepsec parse-failure debug dump\n` +
      `# phase: ${phase}\n` +
      `# agentType: ${agentType}\n` +
      `# timestamp: ${new Date().toISOString()}\n` +
      `# error: ${errMsg}\n` +
      `# batch (${batch?.length ?? 0} files):\n${filesList}\n` +
      `# --- raw agent output begins on next line ---\n`;
    fs.writeFileSync(file, header + resultText, "utf-8");
    return file;
  } catch {
    return undefined;
  }
}

function fileListForRepairPrompt(batch: FileRecord[]): string {
  return batch.map((r) => `- ${r.filePath}`).join("\n");
}

export function buildInvestigateJsonRepairPrompt(batch: FileRecord[]): string {
  return `Your previous response was not valid JSON, so the scanner could not parse it.

Do not redo the investigation and do not use tools. Re-output the same conclusions from your previous response as ONLY one valid JSON array. No prose before or after. No "Confirmed:" preface. A \`\`\`json fenced block is acceptable, but the content inside must be valid JSON.

Keep string values compact. Escape double quotes inside strings as \`\\"\`, escape newlines as \`\\n\`, and do not put raw line breaks inside JSON string values.

Include exactly these target files, with an empty findings array for any file where you found no real issue:

${fileListForRepairPrompt(batch)}

Use this exact schema:

\`\`\`json
[
  {
    "filePath": "relative/path/to/file.ts",
    "findings": [
      {
        "severity": "HIGH",
        "vulnSlug": "the-vuln-slug-or-other",
        "title": "Brief title of the issue",
        "description": "Detailed description of the vulnerability, the attack scenario, and evidence from the code",
        "lineNumbers": [10, 15],
        "recommendation": "How to fix this vulnerability",
        "confidence": "high"
      }
    ]
  }
]
\`\`\`

\`severity\` must be one of \`CRITICAL\`, \`HIGH\`, \`MEDIUM\`, \`HIGH_BUG\`, or \`BUG\`. \`confidence\` must be one of \`high\`, \`medium\`, or \`low\`.`;
}

export function buildRevalidateJsonRepairPrompt(expected?: ExpectedFinding[]): string {
  const idList =
    expected && expected.length > 0
      ? `\nReturn exactly one verdict for every Finding ID below, copying each \`findingId\` exactly:\n\n${expected.map((e) => `- ${e.alias ?? e.findingId} — "${e.title}"`).join("\n")}\n`
      : "";
  return `Your previous response was not valid JSON, so the scanner could not parse it.

Do not redo the revalidation and do not use tools. Re-output the same verdicts and reasoning from your previous response as ONLY one valid JSON array. No prose before or after. No "Confirmed:" preface. A \`\`\`json fenced block is acceptable, but the content inside must be valid JSON.

Keep string values compact. Escape double quotes inside strings as \`\\"\`, escape newlines as \`\\n\`, and do not put raw line breaks inside JSON string values.

Use this exact schema:

\`\`\`json
[
  {
    "findingId": "the exact Finding ID from the finding, e.g. F3",
    "verdict": "true-positive",
    "adjustedSeverity": "HIGH",
    "duplicateOf": "Finding ID of the primary finding (only when verdict is duplicate)",
    "reasoning": "Detailed explanation. Show your work."
  }
]
\`\`\`
${idList}
\`verdict\` must be one of \`true-positive\`, \`false-positive\`, \`fixed\`, \`uncertain\`, or \`duplicate\`. \`adjustedSeverity\` is optional and must be one of \`CRITICAL\`, \`HIGH\`, \`MEDIUM\`, \`HIGH_BUG\`, or \`BUG\` when present. \`duplicateOf\` is required only when \`verdict\` is \`"duplicate"\`; omit it otherwise.`;
}

/**
 * Follow-up prompt for the id-repair turn: the previous response parsed
 * as JSON, but some requested findings got no reconcilable verdict. Ask
 * only for the missing ones, show which returned identifiers didn't
 * match, and echo the unmatched verdicts back so the model mostly just
 * has to fix the ID rather than restate its analysis.
 */
function buildRevalidateIdRepairPrompt(params: {
  appliedCount: number;
  missing: ExpectedFinding[];
  unmatchedVerdicts: RevalidateVerdict[];
}): string {
  const { appliedCount, missing, unmatchedVerdicts } = params;

  const missingList = missing
    .map((e) => `- ${e.alias ?? e.findingId} — ${e.filePath} — "${e.title}"`)
    .join("\n");

  const unknownIdentifiers = unmatchedVerdicts
    .map((v) => v.findingId ?? v.title ?? "")
    .filter(Boolean)
    .map((s) => `- ${JSON.stringify(s)}`)
    .join("\n");
  const unknownBlock = unknownIdentifiers
    ? `\nThe following identifiers from your response could not be matched to any requested finding:\n\n${unknownIdentifiers}\n`
    : "";

  const nearMissBlock =
    unmatchedVerdicts.length > 0
      ? `\nThese verdicts from your previous response could not be matched. If one of them corresponds to a missing finding ID above, re-emit it with the corrected \`findingId\` — keep the verdict and reasoning as they were:\n\n\`\`\`json\n${JSON.stringify(
          unmatchedVerdicts.map((v) => ({
            findingId: v.findingId,
            title: v.title,
            verdict: v.verdict,
            adjustedSeverity: v.adjustedSeverity,
            duplicateOf: v.duplicateOf,
            reasoning: v.reasoning,
          })),
          null,
          2,
        )}\n\`\`\`\n`
      : "";

  return `Your previous response was parsed, and ${appliedCount} verdict(s) were successfully matched to findings.

The following required finding IDs are still missing a verdict:

${missingList}
${unknownBlock}${nearMissBlock}
Return ONLY a JSON array containing verdicts for the missing Finding IDs listed above. Copy each \`findingId\` exactly as shown — do not invent or modify IDs. Preserve your previous conclusions; do not repeat the investigation and do not use tools.

\`\`\`json
[
  {
    "findingId": "F3",
    "verdict": "true-positive" | "false-positive" | "fixed" | "uncertain" | "duplicate",
    "adjustedSeverity": "HIGH",
    "duplicateOf": "Finding ID of the primary finding (only when verdict is duplicate)",
    "reasoning": "Your reasoning from before, compact."
  }
]
\`\`\``;
}

/**
 * In-session id-repair loop, shared by every agent plugin. After the
 * initial revalidation response parses, reconcile it against the
 * requested findings; while any finding is still missing a verdict, ask
 * the SAME session (tool-free) for just the missing ones — up to
 * `maxRepairs` times. The session still holds the full investigation
 * context, so this recovers verdicts the model produced under a mangled
 * identifier without re-running any analysis.
 *
 * Returns the merged verdict list (initial + repair turns; the
 * reconciler's first-match-wins ordering means repaired verdicts only
 * fill gaps, never displace an already-matched verdict) plus the raw
 * responses for artifact logging.
 */
export async function* runRevalidateIdRepairLoop(params: {
  expected: ExpectedFinding[];
  verdicts: RevalidateVerdict[];
  initialRawText: string;
  followUp: ((prompt: string) => Promise<string | undefined>) | undefined;
  agentLabel: string;
  maxRepairs?: number;
}): AsyncGenerator<
  AgentProgress,
  { verdicts: RevalidateVerdict[]; rawResponses: RevalidateRawResponse[]; repairAttempts: number }
> {
  const { expected, initialRawText, followUp, agentLabel, maxRepairs = 2 } = params;
  let verdicts = params.verdicts;
  const rawResponses: RevalidateRawResponse[] = [
    { kind: "initial", rawText: initialRawText, parsedCount: verdicts.length },
  ];
  let repairAttempts = 0;

  while (repairAttempts < maxRepairs) {
    const rec = reconcileVerdicts(expected, verdicts);
    if (rec.missing.length === 0) break;
    if (!followUp) break;

    repairAttempts++;
    yield {
      type: "thinking",
      message: `${agentLabel}: ${rec.missing.length}/${expected.length} verdict(s) missing after reconciliation; requesting id-repair (attempt ${repairAttempts}/${maxRepairs})`,
    };

    const prompt = buildRevalidateIdRepairPrompt({
      appliedCount: rec.matches.length,
      missing: rec.missing,
      unmatchedVerdicts: [...rec.unknown, ...rec.ambiguous],
    });
    const repairText = await followUp(prompt);
    if (repairText === undefined) {
      rawResponses.push({ kind: "id-repair", prompt, rawText: "(follow-up failed)" });
      break;
    }

    let repairVerdicts: RevalidateVerdict[];
    try {
      repairVerdicts = parseRevalidateVerdicts(repairText);
    } catch {
      rawResponses.push({ kind: "id-repair", prompt, rawText: repairText });
      yield {
        type: "thinking",
        message: `${agentLabel}: id-repair response was not parseable JSON; stopping repair`,
      };
      break;
    }
    rawResponses.push({
      kind: "id-repair",
      prompt,
      rawText: repairText,
      parsedCount: repairVerdicts.length,
    });
    if (repairVerdicts.length === 0) break;
    verdicts = [...verdicts, ...repairVerdicts];
  }

  return { verdicts, rawResponses, repairAttempts };
}

export function formatJsonRepairFailureDebugText(originalText: string, repairText: string): string {
  return (
    `# original malformed agent output\n${originalText}\n\n` +
    `# JSON repair follow-up output\n${repairText}`
  );
}

export function jsonRepairFailureError(originalError: unknown, repairError: unknown): Error {
  const original = originalError instanceof Error ? originalError.message : String(originalError);
  const repair = repairError instanceof Error ? repairError.message : String(repairError);
  return new Error(
    `JSON repair follow-up also failed: ${repair}. Original parse error: ${original}`,
  );
}

function extractAgentJsonPayload(resultText: string): string {
  const fenced = resultText.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fenced) return fenced[1].trim();

  const openFence = resultText.match(/```(?:json)?\s*([\s\S]*)$/i);
  if (openFence) return openFence[1].trim();

  return resultText.trim();
}

function extractArrayCandidateForRepair(jsonPayload: string): string {
  const trimmed = jsonPayload.trim();
  if (trimmed.startsWith("[")) return trimmed;

  const arrayStart = /\[\s*(?:\{|\])/.exec(trimmed);
  if (!arrayStart) return trimmed;

  const candidate = trimmed.slice(arrayStart.index);
  const lastClose = candidate.lastIndexOf("]");
  return lastClose >= 0 ? candidate.slice(0, lastClose + 1) : candidate;
}

function parseAgentJsonArray(params: {
  resultText: string;
  parseFailurePrefix: string;
  nonArrayMessage: (parsed: unknown) => string;
}): unknown[] {
  const { resultText, parseFailurePrefix, nonArrayMessage } = params;
  const jsonPayload = extractAgentJsonPayload(resultText);

  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonPayload);
  } catch (strictErr) {
    const repairCandidate = extractArrayCandidateForRepair(jsonPayload);
    try {
      parsed = JSON.parse(jsonrepair(repairCandidate));
    } catch (repairErr) {
      const excerpt = resultText.slice(0, 400).replace(/\s+/g, " ");
      throw new Error(
        `${parseFailurePrefix}: ${strictErr instanceof Error ? strictErr.message : strictErr}. ` +
          `Tolerant jsonrepair failed: ${repairErr instanceof Error ? repairErr.message : repairErr}. ` +
          `First 400 chars: ${excerpt}`,
      );
    }

    if (!Array.isArray(parsed)) {
      const excerpt = resultText.slice(0, 400).replace(/\s+/g, " ");
      throw new Error(
        `${parseFailurePrefix}: ${strictErr instanceof Error ? strictErr.message : strictErr}. ` +
          `Tolerant jsonrepair returned ${typeof parsed}, not an array. ` +
          `First 400 chars: ${excerpt}`,
      );
    }

    return parsed;
  }

  if (!Array.isArray(parsed)) {
    throw new Error(nonArrayMessage(parsed));
  }

  return parsed;
}

/**
 * A finding the agent emitted inside valid JSON but with invalid fields
 * (bad enum value, wrong type, missing required field). Carried out of
 * `parseInvestigateResults` so the caller can request an in-session
 * field-repair instead of the finding being written to disk unvalidated —
 * where the strict read-side schema used to silently erase the whole
 * file's findings.
 */
interface InvalidFindingEntry {
  filePath: string;
  /** The finding as the agent emitted it, verbatim. */
  raw: unknown;
  /** Compact zod issue summary, e.g. `severity: Invalid enum value ...`. */
  issues: string;
}

export interface ParsedInvestigateResults {
  results: InvestigateResult[];
  invalid: InvalidFindingEntry[];
}

export function parseInvestigateResults(
  resultText: string,
  batch: FileRecord[],
): ParsedInvestigateResults {
  // Fail loud when neither strict JSON nor tolerant jsonrepair can produce
  // an array. A malformed response is otherwise indistinguishable from a
  // clean "found nothing" run, which would mask truncation, gateway splice,
  // or prompt-injection-driven non-JSON output.
  const parsed = parseAgentJsonArray({
    resultText,
    parseFailurePrefix: "Agent produced output that wasn't a parseable JSON findings array",
    nonArrayMessage: (parsed) =>
      `Agent produced JSON but not an array of file findings. Got: ${typeof parsed}`,
  });

  const typedParsed = parsed as Array<{ filePath: string; findings: unknown[] }>;
  const results: InvestigateResult[] = [];
  const invalid: InvalidFindingEntry[] = [];
  const batchPaths = new Set(batch.map((r) => r.filePath));

  for (const entry of typedParsed) {
    if (batchPaths.has(entry.filePath)) {
      // Field-validate each finding now, while the session that produced
      // it is still alive and can repair it. Findings used to be written
      // to disk as-emitted; the strict read-side schema then rejected the
      // whole record over one bad field — silently.
      const findings: Finding[] = [];
      for (const raw of entry.findings || []) {
        const parsedFinding = findingSchema.safeParse(raw);
        if (parsedFinding.success) {
          findings.push(parsedFinding.data);
        } else {
          invalid.push({
            filePath: entry.filePath,
            raw,
            issues: formatSchemaIssues(parsedFinding.error),
          });
        }
      }
      results.push({ filePath: entry.filePath, findings });
      batchPaths.delete(entry.filePath);
    }
  }

  for (const filePath of batchPaths) {
    results.push({ filePath, findings: [] });
  }

  return { results, invalid };
}

/**
 * Follow-up prompt for the field-repair turn: the response parsed as JSON
 * and structurally valid findings were kept, but some findings had invalid
 * or missing fields. Echo each invalid finding back with its validation
 * errors so the model mostly just has to fix the offending field.
 */
export function buildInvestigateFieldRepairPrompt(invalid: InvalidFindingEntry[]): string {
  const perFinding = invalid
    .map(
      (e, i) =>
        `### Invalid finding ${i + 1} (filePath: ${JSON.stringify(e.filePath)})\n\n` +
        `Validation errors: ${e.issues}\n\n` +
        `As you emitted it:\n\`\`\`json\n${JSON.stringify(e.raw, null, 2)}\n\`\`\``,
    )
    .join("\n\n");

  return `Your previous response parsed as JSON and its valid findings were accepted, but ${invalid.length} finding(s) had invalid or missing fields and were rejected.

Do not redo the investigation and do not use tools. Re-emit ONLY the rejected findings listed below, corrected to satisfy the schema. Keep the substance (title, description, reasoning) unchanged — fix only the invalid fields.

${perFinding}

Return ONLY a JSON array in this exact shape, containing one entry per filePath with ONLY the corrected findings (do not repeat findings that were already accepted):

\`\`\`json
[
  {
    "filePath": "relative/path/to/file.ts",
    "findings": [
      {
        "severity": "HIGH",
        "vulnSlug": "the-vuln-slug-or-other",
        "title": "Brief title of the issue",
        "description": "Detailed description",
        "lineNumbers": [10, 15],
        "recommendation": "How to fix this vulnerability",
        "confidence": "high"
      }
    ]
  }
]
\`\`\`

\`severity\` must be one of \`CRITICAL\`, \`HIGH\`, \`MEDIUM\`, \`HIGH_BUG\`, or \`BUG\`. \`confidence\` must be one of \`high\`, \`medium\`, or \`low\` (lowercase). \`lineNumbers\` must be an array of numbers. \`title\`, \`description\`, \`recommendation\`, and \`vulnSlug\` must be strings.`;
}

function investigateFindingSignature(f: Finding): string {
  return `${f.vulnSlug}::${f.title.trim().toLowerCase()}`;
}

/**
 * In-session field-repair loop, shared by every agent plugin. When the
 * initial investigation response parses as JSON but some findings fail
 * field validation, keep the valid ones and ask the SAME session
 * (tool-free) to re-emit just the invalid ones, corrected — up to
 * `maxRepairs` times. Repaired findings merge into the kept results by
 * (vulnSlug, title) signature so a model that re-emits an already-accepted
 * finding doesn't duplicate it.
 *
 * Findings still invalid when the loop ends are dropped — loudly: a
 * progress message plus a `writeParseFailureDebug` dump of the offenders.
 */
export async function* runInvestigateFieldRepairLoop(params: {
  results: InvestigateResult[];
  invalid: InvalidFindingEntry[];
  batch: FileRecord[];
  followUp: ((prompt: string) => Promise<string | undefined>) | undefined;
  agentLabel: string;
  agentType: string;
  projectId?: string;
  maxRepairs?: number;
}): AsyncGenerator<AgentProgress, { results: InvestigateResult[]; repairAttempts: number }> {
  const { batch, followUp, agentLabel, agentType, projectId, maxRepairs = 2 } = params;
  const results = params.results;
  let invalid = params.invalid;
  let repairAttempts = 0;

  while (invalid.length > 0 && repairAttempts < maxRepairs && followUp) {
    repairAttempts++;
    yield {
      type: "thinking",
      message: `${agentLabel}: ${invalid.length} finding(s) failed field validation; requesting field-repair (attempt ${repairAttempts}/${maxRepairs})`,
    };

    const prompt = buildInvestigateFieldRepairPrompt(invalid);
    const repairText = await followUp(prompt);
    if (repairText === undefined) break;

    let repaired: ParsedInvestigateResults;
    try {
      repaired = parseInvestigateResults(repairText, batch);
    } catch {
      yield {
        type: "thinking",
        message: `${agentLabel}: field-repair response was not parseable JSON; stopping repair`,
      };
      break;
    }

    for (const entry of repaired.results) {
      if (entry.findings.length === 0) continue;
      const target = results.find((r) => r.filePath === entry.filePath);
      if (!target) continue;
      const seen = new Set(target.findings.map(investigateFindingSignature));
      for (const f of entry.findings) {
        if (!seen.has(investigateFindingSignature(f))) {
          seen.add(investigateFindingSignature(f));
          target.findings.push(f);
        }
      }
    }

    invalid = repaired.invalid;
  }

  if (invalid.length > 0) {
    const summary = invalid
      .map((e) => `${e.filePath}: ${e.issues}`)
      .slice(0, 5)
      .join(" | ");
    yield {
      type: "thinking",
      message: `${agentLabel}: dropping ${invalid.length} finding(s) that failed field validation after ${repairAttempts} repair attempt(s): ${summary}`,
    };
    writeParseFailureDebug({
      projectId,
      phase: "investigate",
      agentType,
      resultText: JSON.stringify(invalid, null, 2),
      error: new Error(
        `${invalid.length} finding(s) failed field validation after ${repairAttempts} field-repair attempt(s)`,
      ),
      batch,
    });
  }

  return { results, repairAttempts };
}

// --- Revalidation prompt ---------------------------------------------------

export function buildRevalidatePrompt(params: {
  batch: FileRecord[];
  projectRoot: string;
  projectInfo: string;
  force: boolean;
  /** See RevalidateParams.onlyFindingIds. */
  onlyFindingIds?: ReadonlySet<string>;
}): { prompt: string; totalFindings: number; expected: ExpectedFinding[] } {
  const { batch, projectRoot, projectInfo, force, onlyFindingIds } = params;
  const filterOpts = { force, onlyFindingIds };

  // Single source of truth for identity AND aliases: the processor
  // reconciles against expectedFindingsForBatch with the same inputs, so
  // the short alias shown here ("F3") maps back to the same findingId on
  // both sides.
  const expected = expectedFindingsForBatch(batch, filterOpts);
  const aliasById = new Map(expected.map((e) => [e.findingId, e.alias]));

  const fileSections: string[] = [];

  for (const file of batch) {
    const findingsToCheck = file.findings.filter((f) => shouldRevalidateFinding(f, filterOpts));
    if (findingsToCheck.length === 0) continue;

    const findingsList = findingsToCheck
      .map((f) => {
        return `### Finding: ${f.title}
- **Finding ID:** ${aliasById.get(f.findingId!) ?? f.findingId}
- **Severity:** ${f.severity}
- **Slug:** ${f.vulnSlug}
- **Lines:** ${f.lineNumbers.join(", ")}
- **Confidence:** ${f.confidence}
- **Description:** ${f.description}
- **Recommendation:** ${f.recommendation}`;
      })
      .join("\n\n");

    let gitContext = "";
    // argv form (no shell) — file.filePath comes from glob output and may
    // contain shell metacharacters (`;`, `$`, backticks). Passing it as a
    // single argv slot keeps it from being re-parsed as a command.
    const gitResult = spawnSync(
      "git",
      ["log", "--oneline", "--since=3 months ago", "-n", "10", "--", file.filePath],
      {
        cwd: projectRoot,
        encoding: "utf-8",
        timeout: 10_000,
        stdio: ["ignore", "pipe", "ignore"],
      },
    );
    if (gitResult.status === 0) {
      const gitLog = (gitResult.stdout ?? "").trim();
      if (gitLog) {
        gitContext = `\n**Recent git history:**\n\`\`\`\n${gitLog}\n\`\`\`\n`;
      }
    }

    fileSections.push(`## File: ${file.filePath}\n\n${findingsList}\n${gitContext}`);
  }

  const totalFindings = expected.length;

  const prompt = `You are a world-class security researcher performing an adversarial review of vulnerability findings. Your goal is to determine, with high confidence, whether each finding is real and exploitable. You must be thorough — incorrect verdicts here directly impact security decisions.

**Take your time.** Read every relevant file. Trace every code path. Do not make assumptions — verify.

**Static analysis only.** Do NOT attempt to reproduce, exploit, or trigger any finding. Do not run the target code, send requests against any endpoint, or execute proof-of-concept scripts. Reach your verdict from the source code alone.

${projectInfo ? `## Project Context\n\n${projectInfo}\n` : ""}

${fileSections.join("\n---\n\n")}

## Investigation Process

For EACH finding, perform ALL of these steps before rendering a verdict:

1. **Read the target file fully** — not just the flagged lines, the entire file
2. **Read all imports that matter** — middleware, auth utilities, validation helpers, the framework's request pipeline
3. **Trace the data flow end-to-end** — Where does the input enter? What transformations happen? Is there validation or sanitization?
4. **Think like an attacker** — Construct a concrete attack scenario. If you can't, it's likely a false positive.
5. **Check for framework-level protections** — Next.js middleware, withSchema auth strategies, CSRF tokens, CORS headers
6. **Check the current code vs. the finding** — Has the vulnerable code been modified or removed? Check git history.
7. **Assess confidence honestly** — If you're not sure, say "uncertain". Don't guess.

## Verdicts

- **true-positive** — Real AND exploitable. You can describe a concrete attack.
- **false-positive** — Not exploitable. Name the specific mitigation.
- **fixed** — Was real but has been patched. Cite the change.
- **uncertain** — Can't determine. Explain what's ambiguous.
- **duplicate** — This finding describes the **same underlying vulnerability** at the **same code location** as another finding in the **same file** (e.g., two matchers flagged the same line range from different angles, or the same auth bypass surfaced twice with different phrasing). Set \`duplicateOf\` to the Finding ID of the primary finding — the one that should keep the canonical verdict. Same vuln class in a different location is **not** a duplicate.

If severity should change, set \`adjustedSeverity\`. Omit if correct.

### Duplicate rules (read carefully)

- \`duplicate\` is only valid within a single file. Cross-file similarity does **not** count.
- For any equivalence class of duplicates, **exactly one finding stays primary** with a real verdict (true-positive / false-positive / fixed / uncertain). The other(s) are \`duplicate\` with \`duplicateOf\` pointing at the primary's Finding ID.
- The primary you reference in \`duplicateOf\` **must itself have a non-duplicate verdict** in your output (or already in the file's prior revalidation). If you mark every member of a group as duplicate, all of them will be rejected.
- Pick the primary as the most precise / highest-confidence statement of the issue. The duplicates should add context in their \`reasoning\`, not repeat the full analysis.

## Output Format

\`\`\`json
[
  {
    "findingId": "the exact Finding ID from the finding, e.g. F3",
    "verdict": "true-positive" | "false-positive" | "fixed" | "uncertain" | "duplicate",
    "adjustedSeverity": "CRITICAL" | "HIGH" | "MEDIUM" | "HIGH_BUG" | "BUG",
    "duplicateOf": "Finding ID of the primary finding (only when verdict is duplicate)",
    "reasoning": "Detailed explanation (5-10 sentences). Show your work."
  }
]
\`\`\`

You must return exactly one verdict for every Finding ID below:

${expected.map((e) => `- ${e.alias ?? e.findingId} — "${e.title}"`).join("\n")}

**Copy each \`findingId\` exactly as shown. Do not invent or modify IDs.** The Finding ID — not the title — is how verdicts are matched back to findings. \`adjustedSeverity\` is optional. \`duplicateOf\` is required iff \`verdict === "duplicate"\` and is otherwise ignored; it must also be a Finding ID.

**Your reasoning is the most important part.** A verdict without thorough reasoning is worthless.`;

  return { prompt, totalFindings, expected };
}

export function parseRevalidateVerdicts(resultText: string): RevalidateVerdict[] {
  // Same fail-loud rationale as parseInvestigateResults: only accept a
  // strict or repaired JSON array. Anything else should mark the batch as
  // errored instead of looking like "no verdicts produced".
  const parsed = parseAgentJsonArray({
    resultText,
    parseFailurePrefix: "Agent produced revalidation output that wasn't parseable JSON",
    nonArrayMessage: (parsed) =>
      `Agent produced revalidation JSON but not an array. Got: ${typeof parsed}`,
  });
  return parsed as RevalidateVerdict[];
}

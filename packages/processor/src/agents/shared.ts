import { spawnSync } from "node:child_process";
import type { FileRecord, RefusalReport } from "@deepsec/core";
import { findingSchema } from "@deepsec/core";
import { z } from "zod";
import type { InvestigateResult, RevalidateVerdict } from "./types.js";

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
 *   - Codex:  `@openai/codex/vendor/.../codex/codex`
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

export function parseInvestigateResults(
  resultText: string,
  batch: FileRecord[],
): InvestigateResult[] {
  const jsonMatch = resultText.match(/```json\s*([\s\S]*?)```/);
  const jsonStr = jsonMatch ? jsonMatch[1].trim() : resultText.trim();

  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonStr);
  } catch (err) {
    // Fail loud — a malformed JSON response is indistinguishable from
    // a "found nothing" run if we silently return empty findings, and
    // for a security tool that's the worst possible failure mode
    // (truncated model output, rate-limit splice, prompt-injection
    // override could all suppress real findings). The processor's
    // batch-level catch fires from this throw, marks files status=error,
    // increments errorBatchCount, and the CLI exits non-zero.
    const excerpt = resultText.slice(0, 400).replace(/\s+/g, " ");
    throw new Error(
      `Agent produced output that wasn't a parseable JSON findings array: ${err instanceof Error ? err.message : err}. ` +
        `First 400 chars: ${excerpt}`,
    );
  }

  if (!Array.isArray(parsed)) {
    throw new Error(`Agent produced JSON but not an array of file findings. Got: ${typeof parsed}`);
  }

  const investigateResultSchema = z.object({
    filePath: z.string(),
    findings: z.array(findingSchema),
  });
  const validation = z.array(investigateResultSchema).safeParse(parsed);
  if (!validation.success) {
    throw new Error(`Agent findings failed schema validation: ${validation.error.message}`);
  }

  const results: InvestigateResult[] = [];
  const batchPaths = new Set(batch.map((r) => r.filePath));

  for (const entry of validation.data) {
    if (batchPaths.has(entry.filePath)) {
      results.push({
        filePath: entry.filePath,
        findings: entry.findings,
      });
      batchPaths.delete(entry.filePath);
    }
  }

  for (const filePath of batchPaths) {
    results.push({ filePath, findings: [] });
  }

  return results;
}

// --- Revalidation prompt ---------------------------------------------------

export function buildRevalidatePrompt(params: {
  batch: FileRecord[];
  projectRoot: string;
  projectInfo: string;
  force: boolean;
}): { prompt: string; totalFindings: number } {
  const { batch, projectRoot, projectInfo, force } = params;

  const fileSections: string[] = [];

  for (const file of batch) {
    const findingsToCheck = file.findings.filter((f) => force || !f.revalidation);
    if (findingsToCheck.length === 0) continue;

    const findingsList = findingsToCheck
      .map((f) => {
        return `### Finding: ${f.title}
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

  const totalFindings = batch.reduce(
    (s, f) => s + f.findings.filter((ff) => force || !ff.revalidation).length,
    0,
  );

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

If severity should change, set \`adjustedSeverity\`. Omit if correct.

## Output Format

\`\`\`json
[
  {
    "filePath": "exact/path/to/file.ts",
    "title": "exact title from the finding",
    "verdict": "true-positive" | "false-positive" | "fixed" | "uncertain",
    "adjustedSeverity": "CRITICAL" | "HIGH" | "MEDIUM" | "HIGH_BUG" | "BUG",
    "reasoning": "Detailed explanation (5-10 sentences). Show your work."
  }
]
\`\`\`

**Include \`filePath\` for every verdict** so we can match verdicts to the correct file. \`adjustedSeverity\` is optional.

**Your reasoning is the most important part.** A verdict without thorough reasoning is worthless.`;

  return { prompt, totalFindings };
}

export function parseRevalidateVerdicts(resultText: string): RevalidateVerdict[] {
  const jsonMatch = resultText.match(/```json\s*([\s\S]*?)```/);
  const jsonStr = jsonMatch ? jsonMatch[1].trim() : resultText.trim();
  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonStr);
  } catch (err) {
    // Same fail-loud rationale as parseInvestigateResults: silently
    // returning [] for malformed output would mark a batch of findings
    // as "no verdicts produced" instead of erroring, suppressing
    // intended revalidation results.
    const excerpt = resultText.slice(0, 400).replace(/\s+/g, " ");
    throw new Error(
      `Agent produced revalidation output that wasn't parseable JSON: ${err instanceof Error ? err.message : err}. ` +
        `First 400 chars: ${excerpt}`,
    );
  }
  if (!Array.isArray(parsed)) {
    throw new Error(`Agent produced revalidation JSON but not an array. Got: ${typeof parsed}`);
  }

  const revalidateVerdictSchema = z.object({
    filePath: z.string(),
    title: z.string(),
    verdict: z.enum(["true-positive", "false-positive", "fixed", "uncertain"]),
    reasoning: z.string(),
    adjustedSeverity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "HIGH_BUG", "BUG"]).optional(),
  });
  const validation = z.array(revalidateVerdictSchema).safeParse(parsed);
  if (!validation.success) {
    throw new Error(
      `Agent revalidation verdicts failed schema validation: ${validation.error.message}`,
    );
  }
  return validation.data as RevalidateVerdict[];
}

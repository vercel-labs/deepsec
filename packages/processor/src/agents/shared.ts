import { spawnSync } from "node:child_process";
import type { FileRecord, Finding, RefusalReport } from "@deepsec/core";
import type { InvestigateResult, RevalidateVerdict } from "./types.js";

// --- Retry / backoff -------------------------------------------------------

export const MAX_ATTEMPTS = 3;

export function isTransientError(msg: string): boolean {
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

  let parsed: Array<{ filePath: string; findings: Finding[] }>;
  try {
    parsed = JSON.parse(jsonStr);
  } catch {
    return batch.map((r) => ({ filePath: r.filePath, findings: [] }));
  }

  const results: InvestigateResult[] = [];
  const batchPaths = new Set(batch.map((r) => r.filePath));

  for (const entry of parsed) {
    if (batchPaths.has(entry.filePath)) {
      results.push({
        filePath: entry.filePath,
        findings: entry.findings || [],
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
  try {
    return JSON.parse(jsonStr) as RevalidateVerdict[];
  } catch {
    return [];
  }
}

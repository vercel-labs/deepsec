import fs from "node:fs";
import path from "node:path";
import { query } from "@anthropic-ai/claude-agent-sdk";
import type { FileRecord, Finding, Severity, TriagePriority } from "@deepsec/core";
import {
  completeRun,
  createRunMeta,
  dataDir,
  defaultConcurrency,
  formatSchemaIssues,
  loadAllFileRecords,
  readProjectConfig,
  writeFileRecord,
  writeRunMeta,
} from "@deepsec/core";
import { z } from "zod";

const TRIAGE_BATCH_SIZE = 30;

interface TriageVerdict {
  title: string;
  priority: TriagePriority;
  exploitability: "trivial" | "moderate" | "difficult";
  impact: "critical" | "high" | "medium" | "low";
  reasoning: string;
}

/**
 * Wire contract for one triage verdict. Enforced at parse time because
 * the apply loop copies these fields verbatim into `finding.triage` —
 * an invalid enum written there makes the finding fail the read-side
 * schema on the next load and get dropped (with a warning) from every
 * report. Triage is a one-shot `query` with no live session, so there is
 * no in-session repair: invalid verdicts are skipped loudly and the
 * finding simply stays untriaged for the next run.
 */
const triageVerdictWireSchema = z.object({
  title: z.string(),
  priority: z.enum(["P0", "P1", "P2", "skip"]),
  exploitability: z.enum(["trivial", "moderate", "difficult"]),
  impact: z.enum(["critical", "high", "medium", "low"]),
  reasoning: z.string(),
});

/**
 * Parse a triage response into field-valid verdicts. Returns the invalid
 * entries alongside so the caller can report them instead of silently
 * writing (or silently skipping) them.
 */
export function parseTriageVerdicts(resultText: string): {
  verdicts: TriageVerdict[];
  invalid: Array<{ raw: unknown; issues: string }>;
} {
  const jsonMatch = resultText.match(/```json\s*([\s\S]*?)```/);
  const jsonStr = jsonMatch ? jsonMatch[1].trim() : resultText.trim();
  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonStr);
  } catch {
    return { verdicts: [], invalid: [] };
  }
  if (!Array.isArray(parsed)) return { verdicts: [], invalid: [] };

  const verdicts: TriageVerdict[] = [];
  const invalid: Array<{ raw: unknown; issues: string }> = [];
  for (const raw of parsed) {
    const v = triageVerdictWireSchema.safeParse(raw);
    if (v.success) verdicts.push(v.data);
    else invalid.push({ raw, issues: formatSchemaIssues(v.error) });
  }
  return { verdicts, invalid };
}

interface TriageProgress {
  type: "batch_started" | "batch_complete" | "all_complete";
  message: string;
}

export async function triage(params: {
  projectId: string;
  severity?: Severity;
  force?: boolean;
  limit?: number;
  concurrency?: number;
  model?: string;
  onProgress?: (progress: TriageProgress) => void;
}): Promise<{ triaged: number; p0: number; p1: number; p2: number; skip: number }> {
  const { projectId, severity = "MEDIUM", force = false, model = "claude-sonnet-4-6" } = params;

  const emit = (progress: TriageProgress) => {
    try {
      params.onProgress?.(progress);
    } catch {}
  };

  const project = readProjectConfig(projectId);

  let projectInfo = "";
  try {
    projectInfo = fs.readFileSync(path.join(dataDir(projectId), "INFO.md"), "utf-8");
  } catch {}

  const startLoad = Date.now();
  emit({ type: "batch_started", message: `Loading file records for ${projectId}...` });
  const records = loadAllFileRecords(projectId);
  emit({
    type: "batch_complete",
    message: `Loaded ${records.length} records in ${((Date.now() - startLoad) / 1000).toFixed(1)}s`,
  });

  emit({ type: "batch_started", message: `Filtering ${severity} findings...` });
  const toTriage: { record: FileRecord; finding: Finding }[] = [];
  let totalFindings = 0;
  let alreadyTriaged = 0;

  for (const record of records) {
    for (const finding of record.findings) {
      if (finding.severity !== severity) continue;
      totalFindings++;
      if (!force && finding.triage) {
        alreadyTriaged++;
        continue;
      }
      toTriage.push({ record, finding });
    }
  }

  if (params.limit && toTriage.length > params.limit) {
    toTriage.splice(params.limit);
  }

  emit({
    type: "batch_complete",
    message: `${totalFindings} ${severity} findings total, ${alreadyTriaged} already triaged, ${toTriage.length} to process`,
  });

  if (toTriage.length === 0) {
    emit({ type: "all_complete", message: "No findings to triage" });
    return { triaged: 0, p0: 0, p1: 0, p2: 0, skip: 0 };
  }

  const meta = createRunMeta({
    projectId,
    rootPath: project.rootPath,
    type: "revalidate",
    processorConfig: { agentType: "triage", model, modelConfig: {} },
  });
  writeRunMeta(meta);

  let totalTriaged = 0;
  let p0 = 0,
    p1 = 0,
    p2 = 0,
    skip = 0;
  let batchesCompleted = 0;
  let batchesInFlight = 0;
  const concurrency = params.concurrency ?? defaultConcurrency();

  const batches: (typeof toTriage)[] = [];
  for (let i = 0; i < toTriage.length; i += TRIAGE_BATCH_SIZE) {
    batches.push(toTriage.slice(i, i + TRIAGE_BATCH_SIZE));
  }

  async function triageBatch(batch: typeof toTriage, batchIdx: number) {
    batchesInFlight++;
    emit({
      type: "batch_started",
      message: `Triaging batch ${batchIdx + 1}/${batches.length} (${batch.length} findings, ${batchesInFlight} in flight)`,
    });

    const findingsList = batch
      .map((item, idx) => {
        return `### ${idx + 1}. ${item.finding.title}
- **File:** \`${item.record.filePath}\`
- **Severity:** ${item.finding.severity}
- **Slug:** ${item.finding.vulnSlug}
- **Lines:** ${item.finding.lineNumbers.join(", ")}
- **Confidence:** ${item.finding.confidence}
- **Description:** ${item.finding.description}`;
      })
      .join("\n\n");

    const prompt = `You are a security triage expert. Given a list of vulnerability findings, classify each by priority for remediation.

${projectInfo ? `## Project Context (summary only)\n\n${projectInfo.slice(0, 2000)}\n` : ""}

## Findings to Triage

${findingsList}

## Classification Criteria

**P0 — Fix immediately:** Exploitable by external attackers with trivial effort. Direct impact on user data, auth bypass, or code execution. No mitigations in place.

**P1 — Fix soon:** Real vulnerability but requires specific conditions (internal access, feature flag enabled, race condition). Moderate impact.

**P2 — Fix eventually:** Low-impact or difficult to exploit. Defense-in-depth improvements. Code quality issues with security implications.

**skip — Not actionable:** False positive, already mitigated, test-only code, or too vague to act on.

## Exploitability scale
- **trivial**: Can be exploited with a single crafted HTTP request or URL
- **moderate**: Requires some setup (valid auth, specific timing, internal network)
- **difficult**: Requires deep knowledge, chained exploits, or unlikely conditions

## Impact scale
- **critical**: Full auth bypass, RCE, data exfiltration across tenants
- **high**: Single-tenant data access, privilege escalation, secret exposure
- **medium**: Information disclosure, DoS, weak crypto
- **low**: Cosmetic, theoretical, or minimal real-world impact

## Output

\`\`\`json
[
  {
    "title": "exact title",
    "priority": "P0" | "P1" | "P2" | "skip",
    "exploitability": "trivial" | "moderate" | "difficult",
    "impact": "critical" | "high" | "medium" | "low",
    "reasoning": "1-2 sentences"
  }
]
\`\`\``;

    try {
      let resultText = "";

      for await (const message of query({
        prompt,
        options: {
          allowedTools: [],
          permissionMode: "dontAsk",
          maxTurns: 1,
          model,
        },
      })) {
        const msg = message as Record<string, any>;
        if (msg.type === "result" && msg.subtype === "success") {
          resultText = msg.result;
        }
      }

      const { verdicts, invalid } = parseTriageVerdicts(resultText);
      for (const inv of invalid) {
        console.warn(`[deepsec] skipping field-invalid triage verdict: ${inv.issues}`);
      }

      for (const verdict of verdicts) {
        const item = batch.find((b) => b.finding.title === verdict.title);
        if (!item) continue;

        item.finding.triage = {
          priority: verdict.priority,
          exploitability: verdict.exploitability,
          impact: verdict.impact,
          reasoning: verdict.reasoning,
          triagedAt: new Date().toISOString(),
          model,
        };
        totalTriaged++;
        if (verdict.priority === "P0") p0++;
        else if (verdict.priority === "P1") p1++;
        else if (verdict.priority === "P2") p2++;
        else skip++;
      }

      const dirtyRecords = new Set(batch.map((b) => b.record));
      for (const record of dirtyRecords) {
        writeFileRecord(record);
      }

      batchesInFlight--;
      batchesCompleted++;
      emit({
        type: "batch_complete",
        message: `Batch ${batchIdx + 1}/${batches.length}: ${verdicts.length} triaged (P0:${verdicts.filter((v) => v.priority === "P0").length} P1:${verdicts.filter((v) => v.priority === "P1").length} P2:${verdicts.filter((v) => v.priority === "P2").length} skip:${verdicts.filter((v) => v.priority === "skip").length}) (${batchesInFlight} in flight, ${batchesCompleted}/${batches.length} done)`,
      });
    } catch (err) {
      batchesInFlight--;
      batchesCompleted++;
      emit({
        type: "batch_complete",
        message: `Batch ${batchIdx + 1}/${batches.length} failed: ${err instanceof Error ? err.message : String(err)} (${batchesInFlight} in flight, ${batchesCompleted}/${batches.length} done)`,
      });
    }
  }

  if (concurrency <= 1) {
    for (let i = 0; i < batches.length; i++) {
      await triageBatch(batches[i], i);
    }
  } else {
    let nextIdx = 0;
    async function worker() {
      while (nextIdx < batches.length) {
        const idx = nextIdx++;
        await triageBatch(batches[idx], idx);
      }
    }
    await Promise.all(
      Array.from({ length: Math.min(concurrency, batches.length) }, () => worker()),
    );
  }

  completeRun(projectId, meta.runId, "done", {
    findingsRevalidated: totalTriaged,
  });

  emit({
    type: "all_complete",
    message: `Triage complete: ${totalTriaged} findings — P0:${p0} P1:${p1} P2:${p2} skip:${skip}`,
  });

  return { triaged: totalTriaged, p0, p1, p2, skip };
}

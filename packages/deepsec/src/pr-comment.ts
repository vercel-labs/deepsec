import { type FileRecord, loadAllFileRecords, type Severity } from "@deepsec/core";

/**
 * Severity ordering used to sort findings within the PR comment. Mirrors
 * the order in `packages/processor/src/index.ts:SEVERITY_ORDER` — keep them
 * in sync if you add a tier.
 */
const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  HIGH_BUG: 3,
  BUG: 4,
  LOW: 5,
};

const SEVERITY_BADGE: Record<Severity, string> = {
  CRITICAL: "🔴 CRITICAL",
  HIGH: "🟠 HIGH",
  MEDIUM: "🟡 MEDIUM",
  HIGH_BUG: "🟣 HIGH BUG",
  BUG: "🟣 BUG",
  LOW: "⚪ LOW",
};

function escapeMarkdownText(value: string): string {
  return value
    .replaceAll("\\", "\\\\")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replace(/([`*_{}[\]()#+\-.!|])/g, "\\$1")
    .replaceAll("@", "&#64;");
}

function inlineCode(value: string): string {
  const normalized = value.replace(/\r?\n/g, " ");
  if (!normalized.includes("`")) return `\`${normalized}\``;
  return `\`\` ${normalized.replaceAll("`", "'")} \`\``;
}

function htmlEscape(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;")
    .replaceAll("@", "&#64;");
}

function htmlCode(value: string): string {
  return `<code>${htmlEscape(value.replace(/\r?\n/g, " "))}</code>`;
}

/**
 * Render a PR-comment-shaped markdown string for the **net-new**
 * findings produced by a specific `process` run. Pre-existing findings
 * on touched files (carried over from prior runs) are intentionally
 * excluded — a PR comment should reflect what this change introduced,
 * not surface old baseline noise.
 *
 * Filtering is by `Finding.producedByRunId === runId` (stamped by the
 * processor when each new finding is appended). Findings written
 * before this field existed have `producedByRunId === undefined` and
 * are always excluded from PR comments.
 *
 * Returns `null` when the run produced no net-new findings; the
 * caller can skip commenting entirely on green runs.
 */
export function renderPrComment(params: {
  projectId: string;
  runId: string;
  /** Free-form origin label, e.g. "git-diff:origin/main". Shown in the header. */
  source?: string;
}): string | null {
  const { projectId, runId, source } = params;
  const records = loadAllFileRecords(projectId);

  const findingsForRun: Array<{
    file: FileRecord;
    finding: NonNullable<FileRecord["findings"]>[number];
  }> = [];

  for (const file of records) {
    for (const f of file.findings ?? []) {
      if (f.producedByRunId !== runId) continue;
      // PR comments surface unresolved risk only — drop anything already
      // resolved (fixed / false-positive / accepted-risk) even if the
      // resolution was set in the same run that produced the finding.
      const v = f.revalidation?.verdict;
      if (v === "accepted-risk" || v === "false-positive" || v === "fixed") continue;
      findingsForRun.push({ file, finding: f });
    }
  }

  if (findingsForRun.length === 0) return null;

  // Sort: severity asc (CRITICAL first), then by file path for stability.
  findingsForRun.sort((a, b) => {
    const sa = SEVERITY_ORDER[a.finding.severity] ?? 99;
    const sb = SEVERITY_ORDER[b.finding.severity] ?? 99;
    if (sa !== sb) return sa - sb;
    if (a.file.filePath !== b.file.filePath) {
      return a.file.filePath < b.file.filePath ? -1 : 1;
    }
    return (a.finding.title ?? "").localeCompare(b.finding.title ?? "");
  });

  // Tally for the header.
  const counts: Partial<Record<Severity, number>> = {};
  for (const { finding } of findingsForRun) {
    counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;
  }
  const tally = (Object.keys(counts) as Severity[])
    .sort((a, b) => (SEVERITY_ORDER[a] ?? 99) - (SEVERITY_ORDER[b] ?? 99))
    .map((s) => `${SEVERITY_BADGE[s]} ×${counts[s]}`)
    .join(" · ");

  const lines: string[] = [];
  lines.push(
    `## 🔎 deepsec found ${findingsForRun.length} finding${findingsForRun.length === 1 ? "" : "s"}`,
  );
  lines.push("");
  lines.push(tally);
  if (source) {
    lines.push("");
    lines.push(`<sub>scope: ${htmlCode(source)} · run ${htmlCode(runId)}</sub>`);
  }
  lines.push("");

  for (const { file, finding } of findingsForRun) {
    const lineRef = finding.lineNumbers?.length
      ? `:L${finding.lineNumbers[0]}${finding.lineNumbers.length > 1 ? `-L${finding.lineNumbers[finding.lineNumbers.length - 1]}` : ""}`
      : "";
    lines.push(
      `### ${SEVERITY_BADGE[finding.severity]} · ${inlineCode(`${file.filePath}${lineRef}`)}`,
    );
    lines.push("");
    lines.push(`**${escapeMarkdownText(finding.title)}**`);
    if (finding.vulnSlug) {
      lines.push(
        `<sub>slug: ${htmlCode(finding.vulnSlug)} · confidence: ${htmlEscape(finding.confidence)}</sub>`,
      );
    }
    lines.push("");
    if (finding.description) {
      lines.push(escapeMarkdownText(truncate(finding.description, 600)));
      lines.push("");
    }
    if (finding.recommendation) {
      lines.push(
        `**Recommendation:** ${escapeMarkdownText(truncate(finding.recommendation, 400))}`,
      );
      lines.push("");
    }
    lines.push("---");
    lines.push("");
  }

  lines.push("<sub>🤖 generated by [deepsec](https://github.com/vercel/deepsec)</sub>");

  return lines.join("\n");
}

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, max - 1).trimEnd() + "…";
}

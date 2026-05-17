import type { FileRecord, Finding, Severity } from "@deepsec/core";
import {
  loadAllFileRecords,
  readProjectConfig,
  reportJsonPath,
  reportMdPath,
  writeDataTextAtomic,
} from "@deepsec/core";
import { BOLD, DIM, RESET, severityColor } from "../formatters.js";
import { resolveProjectId } from "../resolve-project-id.js";

const ACTIONABLE_SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "HIGH_BUG", "BUG"];
const STDOUT_PER_SEVERITY_LIMIT = 10;

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

function lineLabel(lines: number[]): string {
  return lines.length > 0 ? lines.join(", ") : "n/a";
}

function safeConsoleText(value: string, maxChars = 220): string {
  const cleaned = value
    .replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, "")
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, "")
    .replace(/\r?\n/g, " ")
    .replace(/^::/, ": :")
    .trim();
  return cleaned.length <= maxChars ? cleaned : `${cleaned.slice(0, maxChars)}...`;
}

function generateMarkdown(records: FileRecord[], projectId: string): string {
  const allFindings: (Finding & { filePath: string })[] = [];
  for (const r of records) {
    for (const f of r.findings) {
      allFindings.push({ ...f, filePath: r.filePath });
    }
  }

  const bySeverity: Record<Severity, typeof allFindings> = {
    CRITICAL: [],
    HIGH: [],
    MEDIUM: [],
    HIGH_BUG: [],
    BUG: [],
    LOW: [],
  };
  for (const f of allFindings) {
    bySeverity[f.severity].push(f);
  }

  const analyzedCount = records.filter((r) => r.status === "analyzed").length;

  let md = `# Vulnerability Scan Report\n\n`;
  md += `| Field | Value |\n|-------|-------|\n`;
  md += `| Project | ${escapeMarkdownText(projectId)} |\n`;
  md += `| Date | ${new Date().toISOString()} |\n`;
  md += `| Files tracked | ${records.length} |\n`;
  md += `| Files analyzed | ${analyzedCount} |\n`;
  md += `| Total findings | ${allFindings.length} |\n`;
  md += `\n`;

  md += `## Summary\n\n`;
  md += `| Severity | Count |\n|----------|-------|\n`;
  md += `| CRITICAL | ${bySeverity.CRITICAL.length} |\n`;
  md += `| HIGH | ${bySeverity.HIGH.length} |\n`;
  md += `| MEDIUM | ${bySeverity.MEDIUM.length} |\n`;
  md += `| HIGH_BUG | ${bySeverity.HIGH_BUG.length} |\n`;
  md += `| BUG | ${bySeverity.BUG.length} |\n\n`;

  for (const severity of ["CRITICAL", "HIGH", "MEDIUM", "HIGH_BUG", "BUG"] as Severity[]) {
    const findings = bySeverity[severity];
    if (findings.length === 0) continue;

    md += `## ${severity} (${findings.length})\n\n`;
    for (const f of findings) {
      md += `### ${escapeMarkdownText(f.title)}\n\n`;
      const record = records.find((r) => r.filePath === f.filePath);
      md += `- **File:** ${inlineCode(f.filePath)}\n`;
      if (record?.gitInfo?.recentCommitters?.length) {
        const committers = record.gitInfo.recentCommitters
          .map((c) => `${escapeMarkdownText(c.name)} ${inlineCode(c.email)}`)
          .join(", ");
        md += `- **Recent committers:** ${committers}\n`;
      }
      md += `- **Lines:** ${lineLabel(f.lineNumbers)}\n`;
      md += `- **Slug:** ${inlineCode(f.vulnSlug)}\n`;
      md += `- **Confidence:** ${escapeMarkdownText(f.confidence)}\n`;
      if (f.revalidation) {
        const v = f.revalidation;
        const icon =
          v.verdict === "true-positive"
            ? "confirmed"
            : v.verdict === "false-positive"
              ? "~~false positive~~"
              : "uncertain";
        md += `- **Revalidation:** ${icon}\n`;
        md += `- **Reasoning:** ${escapeMarkdownText(v.reasoning)}\n`;
      }
      md += `\n${escapeMarkdownText(f.description)}\n\n`;
      md += `**Recommendation:** ${escapeMarkdownText(f.recommendation)}\n\n`;
      md += `---\n\n`;
    }
  }

  return md;
}

export async function reportCommand(opts: { projectId?: string; runId?: string }) {
  const projectId = resolveProjectId(opts.projectId);

  // readProjectConfig throws if data/<id>/project.json is missing — that's
  // the right behavior here (you can't report on a project that's never
  // been initialized).
  readProjectConfig(projectId);
  let records: FileRecord[] = loadAllFileRecords(projectId);

  if (opts.runId) {
    records = records.filter((r) => r.analysisHistory.some((a) => a.runId === opts.runId));
  }
  records = records.filter((r) => r.status === "analyzed");

  if (records.length === 0) {
    console.log("No analyzed files found. Run `deepsec process` first.");
    return;
  }

  const findingsBySeverity: Record<Severity, (Finding & { filePath: string })[]> = {
    CRITICAL: [],
    HIGH: [],
    MEDIUM: [],
    HIGH_BUG: [],
    BUG: [],
    LOW: [],
  };
  for (const r of records) {
    for (const f of r.findings) {
      findingsBySeverity[f.severity].push({ ...f, filePath: r.filePath });
    }
  }
  const totalFindings = ACTIONABLE_SEVERITIES.reduce(
    (sum, sev) => sum + findingsBySeverity[sev].length,
    0,
  );

  const jsonPath = reportJsonPath(projectId, opts.runId);
  const reportData = {
    projectId,
    generatedAt: new Date().toISOString(),
    runId: opts.runId ?? null,
    summary: {
      filesAnalyzed: records.length,
      totalFindings,
      critical: findingsBySeverity.CRITICAL.length,
      high: findingsBySeverity.HIGH.length,
      medium: findingsBySeverity.MEDIUM.length,
      highBug: findingsBySeverity.HIGH_BUG.length,
      bug: findingsBySeverity.BUG.length,
    },
    files: records.map((r) => ({
      filePath: r.filePath,
      findings: r.findings,
      analysisHistory: r.analysisHistory,
    })),
  };
  writeDataTextAtomic(jsonPath, JSON.stringify(reportData, null, 2) + "\n");

  const mdPath = reportMdPath(projectId, opts.runId);
  writeDataTextAtomic(mdPath, generateMarkdown(records, projectId));

  printStdoutSummary({
    projectId,
    runId: opts.runId,
    records,
    findingsBySeverity,
    totalFindings,
    jsonPath,
    mdPath,
  });
}

function printStdoutSummary(args: {
  projectId: string;
  runId?: string;
  records: FileRecord[];
  findingsBySeverity: Record<Severity, (Finding & { filePath: string })[]>;
  totalFindings: number;
  jsonPath: string;
  mdPath: string;
}) {
  const { projectId, runId, records, findingsBySeverity, totalFindings, jsonPath, mdPath } = args;
  const date = new Date().toISOString().slice(0, 10);

  console.log();
  console.log(`${BOLD}Vulnerability scan report — ${projectId}${RESET}`);
  console.log(`${DIM}Generated ${date}${runId ? ` · run ${runId}` : ""}${RESET}`);
  console.log();
  console.log(`  Files analyzed: ${records.length}`);
  console.log(`  Findings:       ${totalFindings}`);
  console.log();

  // Severity breakdown — show every actionable severity even if zero so the
  // reader sees the shape of the result, not just what fired.
  for (const severity of ACTIONABLE_SEVERITIES) {
    const count = findingsBySeverity[severity].length;
    const padded = severity.padEnd(8);
    const color = count > 0 ? severityColor(severity) : DIM;
    console.log(`  ${color}${padded}${RESET}  ${count}`);
  }

  // Top findings, severity-ordered. Skips false-positive/fixed verdicts —
  // those are noise once revalidate has run.
  for (const severity of ACTIONABLE_SEVERITIES) {
    const findings = findingsBySeverity[severity].filter((f) => {
      const v = f.revalidation?.verdict;
      return v !== "false-positive" && v !== "fixed";
    });
    if (findings.length === 0) continue;

    console.log();
    console.log(`${severityColor(severity)}${BOLD}${severity}${RESET} (${findings.length})`);
    for (const f of findings.slice(0, STDOUT_PER_SEVERITY_LIMIT)) {
      const lines = f.lineNumbers.length > 0 ? `:${f.lineNumbers[0]}` : "";
      console.log(`  • ${safeConsoleText(f.title)}`);
      console.log(`    ${DIM}${safeConsoleText(f.filePath, 300)}${lines}${RESET}`);
    }
    const remaining = findings.length - STDOUT_PER_SEVERITY_LIMIT;
    if (remaining > 0) {
      console.log(`    ${DIM}… and ${remaining} more${RESET}`);
    }
  }

  console.log();
  console.log(`${DIM}Reports written:${RESET}`);
  console.log(`  ${jsonPath}`);
  console.log(`  ${mdPath}`);
}

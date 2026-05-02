import fs from "node:fs";
import path from "node:path";
import { getDataRoot, loadAllFileRecords } from "@deepsec/core";
import { BOLD, DIM, GREEN, RED, RESET, YELLOW } from "../formatters.js";

const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  HIGH_BUG: 3,
  BUG: 4,
  LOW: 5,
};

interface ProjectMetrics {
  projectId: string;
  totalFiles: number;
  analyzed: number;
  pending: number;
  findings: number;
  bySeverity: Record<string, number>;
  byVulnType: Record<string, number>;
  byVulnTypeTP: Record<string, number>;
  revalidation: { tp: number; fp: number; fixed: number; uncertain: number; pending: number };
}

function discoverProjects(): string[] {
  const dataDir = path.resolve(getDataRoot());
  if (!fs.existsSync(dataDir)) return [];
  return fs
    .readdirSync(dataDir, { withFileTypes: true })
    .filter((e) => e.isDirectory() && fs.existsSync(path.join(dataDir, e.name, "project.json")))
    .map((e) => e.name)
    .sort();
}

function getMetrics(projectId: string, minSeverity?: string): ProjectMetrics {
  const minOrder = minSeverity ? (SEVERITY_ORDER[minSeverity] ?? 2) : 99;
  const records = loadAllFileRecords(projectId);

  const m: ProjectMetrics = {
    projectId,
    totalFiles: records.length,
    analyzed: records.filter((r) => r.status === "analyzed").length,
    pending: records.filter((r) => r.status === "pending" || r.status === "error").length,
    findings: 0,
    bySeverity: {},
    byVulnType: {},
    byVulnTypeTP: {},
    revalidation: { tp: 0, fp: 0, fixed: 0, uncertain: 0, pending: 0 },
  };

  for (const record of records) {
    for (const f of record.findings) {
      if (SEVERITY_ORDER[f.severity] > minOrder) continue;
      m.findings++;
      m.bySeverity[f.severity] = (m.bySeverity[f.severity] || 0) + 1;
      const slug = f.vulnSlug || "unknown";
      m.byVulnType[slug] = (m.byVulnType[slug] || 0) + 1;

      const verdict = f.revalidation?.verdict;
      if (verdict === "true-positive") {
        m.revalidation.tp++;
        m.byVulnTypeTP[slug] = (m.byVulnTypeTP[slug] || 0) + 1;
      } else if (verdict === "false-positive") m.revalidation.fp++;
      else if (verdict === "fixed") m.revalidation.fixed++;
      else if (verdict === "uncertain") m.revalidation.uncertain++;
      else m.revalidation.pending++;
    }
  }

  return m;
}

// --- Table helpers ---

function line(width: number): string {
  return "─".repeat(width);
}

function row(cols: string[], widths: number[], alignRight: number[] = []): string {
  return (
    "│ " +
    cols
      .map((c, i) => {
        const stripped = c.replace(/\x1b\[[0-9;]*m/g, "");
        const pad = widths[i] - stripped.length;
        if (alignRight.includes(i)) return " ".repeat(Math.max(0, pad)) + c;
        return c + " ".repeat(Math.max(0, pad));
      })
      .join(" │ ") +
    " │"
  );
}

function headerRow(cols: string[], widths: number[]): string {
  return (
    `┌${"┬".padStart(0)}${widths.map((w) => line(w + 2)).join("┬")}┐\n` +
    row(
      cols.map((c) => `${BOLD}${c}${RESET}`),
      widths,
    ) +
    "\n" +
    `├${widths.map((w) => line(w + 2)).join("┼")}┤`
  );
}

function footerRow(widths: number[]): string {
  return `└${widths.map((w) => line(w + 2)).join("┴")}┘`;
}

export function metricsCommand(opts: { projectId?: string; minSeverity?: string }) {
  const projectIds = opts.projectId ? [opts.projectId] : discoverProjects();
  const minSev = opts.minSeverity ?? "LOW";

  const allMetrics = projectIds
    .filter((id) => {
      try {
        return getMetrics(id, minSev);
      } catch {
        return null;
      }
    })
    .map((id) => getMetrics(id, minSev));

  console.log(`\n${BOLD}Vulnerability Metrics${RESET} (min severity: ${minSev})\n`);

  // --- Project summary table ---
  const projW = [22, 7, 6, 6, 5, 5, 5, 5];
  const projH = ["Project", "Files", "CRIT", "HIGH", "TP", "FP", "Pend", "Unc"];
  const rightCols = [1, 2, 3, 4, 5, 6, 7];

  console.log(headerRow(projH, projW));

  const totals = {
    files: 0,
    crit: 0,
    high: 0,
    tp: 0,
    fp: 0,
    pend: 0,
    unc: 0,
    totalFindings: 0,
    analyzed: 0,
    pending: 0,
    bySeverity: {} as Record<string, number>,
    byVulnType: {} as Record<string, number>,
    byVulnTypeTP: {} as Record<string, number>,
  };

  for (const m of allMetrics) {
    const crit = m.bySeverity.CRITICAL || 0;
    const high = m.bySeverity.HIGH || 0;
    const r = m.revalidation;

    console.log(
      row(
        [
          m.projectId,
          String(m.totalFiles),
          crit > 0 ? `${RED}${crit}${RESET}` : `${DIM}0${RESET}`,
          high > 0 ? `${YELLOW}${high}${RESET}` : `${DIM}0${RESET}`,
          r.tp > 0 ? `${GREEN}${r.tp}${RESET}` : `${DIM}0${RESET}`,
          r.fp > 0 ? `${RED}${r.fp}${RESET}` : `${DIM}0${RESET}`,
          r.pending > 0 ? String(r.pending) : `${DIM}0${RESET}`,
          r.uncertain > 0 ? String(r.uncertain) : `${DIM}0${RESET}`,
        ],
        projW,
        rightCols,
      ),
    );

    totals.files += m.totalFiles;
    totals.analyzed += m.analyzed;
    totals.pending += m.pending;
    totals.crit += crit;
    totals.high += high;
    totals.tp += r.tp;
    totals.fp += r.fp;
    totals.pend += r.pending;
    totals.unc += r.uncertain;
    totals.totalFindings += m.findings;
    for (const [sev, count] of Object.entries(m.bySeverity)) {
      totals.bySeverity[sev] = (totals.bySeverity[sev] || 0) + count;
    }
    for (const [slug, count] of Object.entries(m.byVulnType)) {
      totals.byVulnType[slug] = (totals.byVulnType[slug] || 0) + count;
    }
    for (const [slug, count] of Object.entries(m.byVulnTypeTP)) {
      totals.byVulnTypeTP[slug] = (totals.byVulnTypeTP[slug] || 0) + count;
    }
  }

  console.log(`├${projW.map((w) => line(w + 2)).join("┼")}┤`);
  console.log(
    row(
      [
        `${BOLD}TOTAL${RESET}`,
        `${BOLD}${totals.files}${RESET}`,
        `${BOLD}${RED}${totals.crit}${RESET}`,
        `${BOLD}${YELLOW}${totals.high}${RESET}`,
        `${BOLD}${GREEN}${totals.tp}${RESET}`,
        `${BOLD}${RED}${totals.fp}${RESET}`,
        `${BOLD}${totals.pend}${RESET}`,
        `${BOLD}${totals.unc}${RESET}`,
      ],
      projW,
      rightCols,
    ),
  );
  console.log(footerRow(projW));

  // --- Vuln type table ---
  console.log(`\n${BOLD}True Positives by Vulnerability Type${RESET}\n`);

  const vtW = [30, 4, 5, 5];
  const vtH = ["Category", "TP", "Total", "Rate"];
  console.log(headerRow(vtH, vtW));

  // Separate named matchers from other-* and collect other-* into a bucket
  const vulnTypes = Object.entries(totals.byVulnType).sort(
    (a, b) => (totals.byVulnTypeTP[b[0]] || 0) - (totals.byVulnTypeTP[a[0]] || 0),
  );

  let otherTP = 0;
  let otherTotal = 0;
  let otherCount = 0;

  for (const [slug, total] of vulnTypes) {
    const tp = totals.byVulnTypeTP[slug] || 0;
    const isOther = slug.startsWith("other-");

    // Roll up low-occurrence other-* into a single "other (misc)" row
    if (isOther && tp <= 2) {
      otherTP += tp;
      otherTotal += total;
      otherCount++;
      continue;
    }

    if (tp === 0) continue;

    const rate = total > 0 ? Math.round((tp / total) * 100) : 0;
    const rateStr =
      rate === 100
        ? `${GREEN}${rate}%${RESET}`
        : rate >= 90
          ? `${YELLOW}${rate}%${RESET}`
          : `${rate}%`;

    console.log(row([slug, `${GREEN}${tp}${RESET}`, String(total), rateStr], vtW, [1, 2, 3]));
  }

  // Print the rolled-up other row
  if (otherCount > 0 && otherTP > 0) {
    const rate = otherTotal > 0 ? Math.round((otherTP / otherTotal) * 100) : 0;
    console.log(
      row(
        [
          `${DIM}other (${otherCount} categories)${RESET}`,
          `${GREEN}${otherTP}${RESET}`,
          String(otherTotal),
          `${rate}%`,
        ],
        vtW,
        [1, 2, 3],
      ),
    );
  }

  console.log(footerRow(vtW));

  console.log();
  console.log(`${DIM}Files: ${totals.analyzed} analyzed, ${totals.pending} pending${RESET}`);
  console.log();
}

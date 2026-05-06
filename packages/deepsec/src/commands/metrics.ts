import fs from "node:fs";
import path from "node:path";
import { getDataRoot, loadAllFileRecords } from "@deepsec/core";
import { BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW } from "../formatters.js";

const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  HIGH_BUG: 3,
  BUG: 4,
  LOW: 5,
};

interface TokenStats {
  input: number;
  output: number;
  cacheRead: number;
  cacheCreation: number;
}

interface AgentStats {
  analyses: number;
  cost: number;
  durationMs: number;
  turns: number;
  tokens: TokenStats;
}

interface ProjectMetrics {
  projectId: string;
  totalFiles: number;
  analyzed: number;
  pending: number;
  findings: number;
  bySeverity: Record<string, number>;
  byVulnType: Record<string, number>;
  byVulnTypeTP: Record<string, number>;
  byTriage: Record<string, number>;
  revalidation: { tp: number; fp: number; fixed: number; uncertain: number; pending: number };
  cost: number;
  analysisCount: number;
  tokens: TokenStats;
  byAgent: Record<string, AgentStats>;
}

function emptyTokens(): TokenStats {
  return { input: 0, output: 0, cacheRead: 0, cacheCreation: 0 };
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
    byTriage: {},
    revalidation: { tp: 0, fp: 0, fixed: 0, uncertain: 0, pending: 0 },
    cost: 0,
    analysisCount: 0,
    tokens: emptyTokens(),
    byAgent: {},
  };

  for (const record of records) {
    // Findings — severity / vulntype / triage / revalidation rollups
    for (const f of record.findings) {
      if (SEVERITY_ORDER[f.severity] > minOrder) continue;
      m.findings++;
      m.bySeverity[f.severity] = (m.bySeverity[f.severity] || 0) + 1;
      const slug = f.vulnSlug || "unknown";
      m.byVulnType[slug] = (m.byVulnType[slug] || 0) + 1;

      if (f.triage?.priority) {
        m.byTriage[f.triage.priority] = (m.byTriage[f.triage.priority] || 0) + 1;
      }

      const verdict = f.revalidation?.verdict;
      if (verdict === "true-positive") {
        m.revalidation.tp++;
        m.byVulnTypeTP[slug] = (m.byVulnTypeTP[slug] || 0) + 1;
      } else if (verdict === "false-positive") m.revalidation.fp++;
      else if (verdict === "fixed") m.revalidation.fixed++;
      else if (verdict === "uncertain") m.revalidation.uncertain++;
      else m.revalidation.pending++;
    }

    // Analysis history — cost / tokens / agent breakdown. These don't depend
    // on `--min-severity`: cost and capacity are about the work done, not
    // about which findings the user wants to look at right now.
    for (const a of record.analysisHistory) {
      m.analysisCount++;
      m.cost += a.costUsd ?? 0;
      const u = a.usage;
      if (u) {
        m.tokens.input += u.inputTokens;
        m.tokens.output += u.outputTokens;
        m.tokens.cacheRead += u.cacheReadInputTokens;
        m.tokens.cacheCreation += u.cacheCreationInputTokens;
      }

      const agentKey = a.model ? `${a.agentType} / ${a.model}` : a.agentType;
      const stats = (m.byAgent[agentKey] ??= {
        analyses: 0,
        cost: 0,
        durationMs: 0,
        turns: 0,
        tokens: emptyTokens(),
      });
      stats.analyses++;
      stats.cost += a.costUsd ?? 0;
      stats.durationMs += a.durationMs ?? 0;
      stats.turns += a.numTurns ?? 0;
      if (u) {
        stats.tokens.input += u.inputTokens;
        stats.tokens.output += u.outputTokens;
        stats.tokens.cacheRead += u.cacheReadInputTokens;
        stats.tokens.cacheCreation += u.cacheCreationInputTokens;
      }
    }
  }

  return m;
}

// --- Number formatting ---

export function formatCost(n: number): string {
  if (n === 0) return "$0";
  if (n < 0.01) return `$${n.toFixed(4)}`;
  if (n < 1) return `$${n.toFixed(3)}`;
  if (n < 100) return `$${n.toFixed(2)}`;
  return `$${n.toFixed(0)}`;
}

export function formatTokens(n: number): string {
  if (n === 0) return "0";
  if (n < 1000) return String(n);
  if (n < 1_000_000) return `${(n / 1000).toFixed(1)}K`;
  if (n < 1_000_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  return `${(n / 1_000_000_000).toFixed(1)}B`;
}

export function formatPct(numerator: number, denominator: number): string {
  if (denominator === 0) return "—";
  return `${Math.round((numerator / denominator) * 100)}%`;
}

/**
 * Cache hit rate = cached input / total input.
 *
 * `inputTokens` is the *uncached* portion (Anthropic convention; the codex
 * adapter normalizes to match), so total input is the sum of all three
 * buckets. `cacheCreation` tokens are uncached too — they're paying full
 * price to populate the cache for next time.
 */
export function formatCacheHitRate(tokens: {
  input: number;
  cacheRead: number;
  cacheCreation: number;
}): string {
  const totalInput = tokens.input + tokens.cacheRead + tokens.cacheCreation;
  return formatPct(tokens.cacheRead, totalInput);
}

// --- Table helpers ---

function line(width: number): string {
  return "─".repeat(width);
}

function visibleLength(s: string): number {
  return s.replace(/\x1b\[[0-9;]*m/g, "").length;
}

function row(cols: string[], widths: number[], alignRight: number[] = []): string {
  return (
    "│ " +
    cols
      .map((c, i) => {
        const pad = widths[i] - visibleLength(c);
        if (alignRight.includes(i)) return " ".repeat(Math.max(0, pad)) + c;
        return c + " ".repeat(Math.max(0, pad));
      })
      .join(" │ ") +
    " │"
  );
}

function headerRow(cols: string[], widths: number[]): string {
  return (
    `┌${widths.map((w) => line(w + 2)).join("┬")}┐\n` +
    row(
      cols.map((c) => `${BOLD}${c}${RESET}`),
      widths,
    ) +
    "\n" +
    `├${widths.map((w) => line(w + 2)).join("┼")}┤`
  );
}

function midRow(widths: number[]): string {
  return `├${widths.map((w) => line(w + 2)).join("┼")}┤`;
}

function footerRow(widths: number[]): string {
  return `└${widths.map((w) => line(w + 2)).join("┴")}┘`;
}

function dimZero(n: number, color?: string): string {
  if (n === 0) return `${DIM}0${RESET}`;
  if (color) return `${color}${n}${RESET}`;
  return String(n);
}

export function metricsCommand(opts: { projectId?: string; minSeverity?: string }) {
  const projectIds = opts.projectId ? [opts.projectId] : discoverProjects();
  const minSev = opts.minSeverity ?? "LOW";

  const allMetrics: ProjectMetrics[] = [];
  for (const id of projectIds) {
    try {
      allMetrics.push(getMetrics(id, minSev));
    } catch {
      // skip projects that fail to load
    }
  }

  console.log(`\n${BOLD}Vulnerability Metrics${RESET} (min severity: ${minSev})\n`);

  // --- Section 1: Per-project findings by severity + revalidation status ---
  // Columns: every severity bucket so a glance answers "where do these
  // findings sit?", plus TP/FP from revalidation. Pending/Uncertain were
  // dropped from this row — they live in the cost/triage tables below.
  const sevW = [22, 6, 5, 5, 5, 5, 5, 5, 5, 5, 5];
  const sevH = [
    "Project",
    "Files",
    "Done",
    "CRIT",
    "HIGH",
    "MED",
    "HBUG",
    "BUG",
    "LOW",
    "TP",
    "FP",
  ];
  const sevRightCols = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

  console.log(headerRow(sevH, sevW));

  const totals = {
    files: 0,
    analyzed: 0,
    pending: 0,
    bySeverity: {} as Record<string, number>,
    tp: 0,
    fp: 0,
    revPending: 0,
    revUnc: 0,
    fixed: 0,
    cost: 0,
    analysisCount: 0,
    tokens: emptyTokens(),
    byVulnType: {} as Record<string, number>,
    byVulnTypeTP: {} as Record<string, number>,
    byTriage: {} as Record<string, number>,
    byAgent: {} as Record<string, AgentStats>,
  };

  for (const m of allMetrics) {
    const sev = m.bySeverity;
    const r = m.revalidation;
    console.log(
      row(
        [
          m.projectId,
          String(m.totalFiles),
          dimZero(m.analyzed),
          dimZero(sev.CRITICAL || 0, RED),
          dimZero(sev.HIGH || 0, YELLOW),
          dimZero(sev.MEDIUM || 0, CYAN),
          dimZero(sev.HIGH_BUG || 0),
          dimZero(sev.BUG || 0),
          dimZero(sev.LOW || 0),
          dimZero(r.tp, GREEN),
          dimZero(r.fp, RED),
        ],
        sevW,
        sevRightCols,
      ),
    );

    totals.files += m.totalFiles;
    totals.analyzed += m.analyzed;
    totals.pending += m.pending;
    totals.tp += r.tp;
    totals.fp += r.fp;
    totals.revPending += r.pending;
    totals.revUnc += r.uncertain;
    totals.fixed += r.fixed;
    totals.cost += m.cost;
    totals.analysisCount += m.analysisCount;
    totals.tokens.input += m.tokens.input;
    totals.tokens.output += m.tokens.output;
    totals.tokens.cacheRead += m.tokens.cacheRead;
    totals.tokens.cacheCreation += m.tokens.cacheCreation;

    for (const [k, v] of Object.entries(m.bySeverity)) {
      totals.bySeverity[k] = (totals.bySeverity[k] || 0) + v;
    }
    for (const [k, v] of Object.entries(m.byVulnType)) {
      totals.byVulnType[k] = (totals.byVulnType[k] || 0) + v;
    }
    for (const [k, v] of Object.entries(m.byVulnTypeTP)) {
      totals.byVulnTypeTP[k] = (totals.byVulnTypeTP[k] || 0) + v;
    }
    for (const [k, v] of Object.entries(m.byTriage)) {
      totals.byTriage[k] = (totals.byTriage[k] || 0) + v;
    }
    for (const [agent, s] of Object.entries(m.byAgent)) {
      const t = (totals.byAgent[agent] ??= {
        analyses: 0,
        cost: 0,
        durationMs: 0,
        turns: 0,
        tokens: emptyTokens(),
      });
      t.analyses += s.analyses;
      t.cost += s.cost;
      t.durationMs += s.durationMs;
      t.turns += s.turns;
      t.tokens.input += s.tokens.input;
      t.tokens.output += s.tokens.output;
      t.tokens.cacheRead += s.tokens.cacheRead;
      t.tokens.cacheCreation += s.tokens.cacheCreation;
    }
  }

  if (allMetrics.length > 1) {
    const t = totals;
    console.log(midRow(sevW));
    console.log(
      row(
        [
          `${BOLD}TOTAL${RESET}`,
          `${BOLD}${t.files}${RESET}`,
          `${BOLD}${t.analyzed}${RESET}`,
          `${BOLD}${RED}${t.bySeverity.CRITICAL || 0}${RESET}`,
          `${BOLD}${YELLOW}${t.bySeverity.HIGH || 0}${RESET}`,
          `${BOLD}${CYAN}${t.bySeverity.MEDIUM || 0}${RESET}`,
          `${BOLD}${t.bySeverity.HIGH_BUG || 0}${RESET}`,
          `${BOLD}${t.bySeverity.BUG || 0}${RESET}`,
          `${BOLD}${t.bySeverity.LOW || 0}${RESET}`,
          `${BOLD}${GREEN}${t.tp}${RESET}`,
          `${BOLD}${RED}${t.fp}${RESET}`,
        ],
        sevW,
        sevRightCols,
      ),
    );
  }
  console.log(footerRow(sevW));

  // --- Section 2: Cost & Tokens ---
  // Costs come from analysisHistory across every record, regardless of
  // --min-severity. A run that produced no findings still incurred cost.
  if (totals.analysisCount > 0) {
    console.log(`\n${BOLD}Cost & Tokens${RESET}\n`);

    const costW = [22, 9, 10, 8, 8, 9, 11];
    const costH = ["Project", "Analyses", "Cost", "Input", "Output", "Cache Hit", "$/Analysis"];
    const costRight = [1, 2, 3, 4, 5, 6];
    console.log(headerRow(costH, costW));

    for (const m of allMetrics) {
      if (m.analysisCount === 0) continue;
      const cacheHit = formatCacheHitRate(m.tokens);
      const perAnalysis = m.cost / m.analysisCount;
      console.log(
        row(
          [
            m.projectId,
            String(m.analysisCount),
            formatCost(m.cost),
            formatTokens(m.tokens.input),
            formatTokens(m.tokens.output),
            cacheHit,
            formatCost(perAnalysis),
          ],
          costW,
          costRight,
        ),
      );
    }

    if (allMetrics.filter((m) => m.analysisCount > 0).length > 1) {
      console.log(midRow(costW));
      const cacheHit = formatCacheHitRate(totals.tokens);
      const perAnalysis = totals.analysisCount > 0 ? totals.cost / totals.analysisCount : 0;
      console.log(
        row(
          [
            `${BOLD}TOTAL${RESET}`,
            `${BOLD}${totals.analysisCount}${RESET}`,
            `${BOLD}${formatCost(totals.cost)}${RESET}`,
            `${BOLD}${formatTokens(totals.tokens.input)}${RESET}`,
            `${BOLD}${formatTokens(totals.tokens.output)}${RESET}`,
            `${BOLD}${cacheHit}${RESET}`,
            `${BOLD}${formatCost(perAnalysis)}${RESET}`,
          ],
          costW,
          costRight,
        ),
      );
    }
    console.log(footerRow(costW));
  }

  // --- Section 3: Cost by Agent / Model (rolled up across projects) ---
  const agentEntries = Object.entries(totals.byAgent).sort((a, b) => b[1].cost - a[1].cost);
  if (agentEntries.length > 0) {
    console.log(`\n${BOLD}By Agent / Model${RESET}\n`);

    const agW = [36, 9, 10, 11, 8];
    const agH = ["Agent / Model", "Analyses", "Cost", "$/Analysis", "Avg Turns"];
    const agRight = [1, 2, 3, 4];
    console.log(headerRow(agH, agW));
    for (const [agent, s] of agentEntries) {
      const avgCost = s.cost / s.analyses;
      const avgTurns = s.analyses > 0 ? (s.turns / s.analyses).toFixed(1) : "—";
      console.log(
        row(
          [agent, String(s.analyses), formatCost(s.cost), formatCost(avgCost), avgTurns],
          agW,
          agRight,
        ),
      );
    }
    console.log(footerRow(agW));
  }

  // --- Section 4: Triage Breakdown (only if any finding was triaged) ---
  const triageTotal = Object.values(totals.byTriage).reduce((a, b) => a + b, 0);
  if (triageTotal > 0) {
    console.log(`\n${BOLD}Triage Breakdown${RESET}\n`);

    const trW = [22, 5, 5, 5, 6];
    const trH = ["Project", "P0", "P1", "P2", "Skip"];
    const trRight = [1, 2, 3, 4];
    console.log(headerRow(trH, trW));
    for (const m of allMetrics) {
      const t = m.byTriage;
      if (Object.values(t).reduce((a, b) => a + b, 0) === 0) continue;
      console.log(
        row(
          [
            m.projectId,
            dimZero(t.P0 || 0, RED),
            dimZero(t.P1 || 0, YELLOW),
            dimZero(t.P2 || 0),
            dimZero(t.skip || 0),
          ],
          trW,
          trRight,
        ),
      );
    }
    console.log(footerRow(trW));
  }

  // --- Section 5: True Positives by Vulnerability Type (existing, retained) ---
  if (totals.tp > 0) {
    console.log(`\n${BOLD}True Positives by Vulnerability Type${RESET}\n`);

    const vtW = [30, 4, 5, 5];
    const vtH = ["Category", "TP", "Total", "Rate"];
    console.log(headerRow(vtH, vtW));

    const vulnTypes = Object.entries(totals.byVulnType).sort(
      (a, b) => (totals.byVulnTypeTP[b[0]] || 0) - (totals.byVulnTypeTP[a[0]] || 0),
    );

    let otherTP = 0;
    let otherTotal = 0;
    let otherCount = 0;

    for (const [slug, total] of vulnTypes) {
      const tp = totals.byVulnTypeTP[slug] || 0;
      const isOther = slug.startsWith("other-");

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
  }

  // --- Footer ---
  const footerBits: string[] = [];
  footerBits.push(`Files: ${totals.analyzed} analyzed, ${totals.pending} pending`);
  if (totals.revPending > 0) footerBits.push(`${totals.revPending} findings pending revalidation`);
  if (totals.revUnc > 0) footerBits.push(`${totals.revUnc} uncertain`);
  if (totals.fixed > 0) footerBits.push(`${totals.fixed} fixed`);
  console.log();
  console.log(`${DIM}${footerBits.join(" • ")}${RESET}`);
  console.log();
}

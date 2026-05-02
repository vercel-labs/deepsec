import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { FileRecord, Finding, Severity } from "@deepsec/core";
import { dataDir, getDataRoot, loadAllFileRecords } from "@deepsec/core";
import { BOLD, DIM, GREEN, RESET, YELLOW } from "../formatters.js";

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  HIGH_BUG: 2,
  MEDIUM: 3,
  BUG: 4,
  LOW: 5,
};

interface OwnerSummary {
  assignee?: string;
  assigneeSource?: "oncall" | "manager" | "top-contributor" | "last-committer";
  teams: { name: string; slug: string }[];
  oncall: { name: string; email: string; slack_user_id?: string; github_username?: string }[];
  managers: { email: string; slack_user_id?: string }[];
  contributors: { name: string; email: string; github_username?: string; score: number }[];
  recentCommitters: { name: string; email: string; date: string }[];
}

interface ExportedFinding {
  title: string;
  description: string;
  severity: Severity;
  labels: string[];
  /** Best-guess owner email, suitable for downstream issue-tracker assignment. */
  assignee?: string;
  metadata: {
    projectId: string;
    filePath: string;
    lineNumbers: number[];
    severity: Severity;
    vulnSlug: string;
    confidence: string;
    discoveredAt: string;
    runId: string;
    revalidation?: {
      verdict: string;
      reasoning: string;
    };
    githubUrl?: string;
    owners: OwnerSummary;
  };
}

function summarizeOwners(record: FileRecord): OwnerSummary {
  const teams = (record.gitInfo?.ownership?.escalationTeams ?? []).map((t) => ({
    name: t.name,
    slug: t.slug,
  }));
  const oncall = (record.gitInfo?.ownership?.escalationTeams ?? [])
    .map((t) => t.current_oncall)
    .filter((o) => o?.email)
    .map((o) => ({
      name: o.name,
      email: o.email,
      slack_user_id: o.slack_user_id,
      github_username: o.github_username,
    }));
  const managers = (record.gitInfo?.ownership?.escalationTeams ?? [])
    .map((t) => t.manager)
    .filter((m) => m?.email)
    .map((m) => ({ email: m.email, slack_user_id: m.slack_user_id }));
  const contributors = (record.gitInfo?.ownership?.contributors ?? []).slice(0, 5).map((c) => ({
    name: c.name,
    email: c.email,
    github_username: c.github_username,
    score: c.score,
  }));
  const recentCommitters = (record.gitInfo?.recentCommitters ?? []).slice(0, 5);

  let assignee: string | undefined;
  let assigneeSource: OwnerSummary["assigneeSource"];
  if (oncall[0]?.email) {
    assignee = oncall[0].email;
    assigneeSource = "oncall";
  } else if (managers[0]?.email) {
    assignee = managers[0].email;
    assigneeSource = "manager";
  } else if (contributors[0]?.email) {
    assignee = contributors[0].email;
    assigneeSource = "top-contributor";
  } else if (recentCommitters[0]?.email) {
    assignee = recentCommitters[0].email;
    assigneeSource = "last-committer";
  }

  return { assignee, assigneeSource, teams, oncall, managers, contributors, recentCommitters };
}

function projectRepoUrl(projectId: string): string | undefined {
  try {
    const p = JSON.parse(fs.readFileSync(path.join(dataDir(projectId), "project.json"), "utf-8"));
    return p.githubUrl;
  } catch {
    return undefined;
  }
}

function makeGithubLink(
  repoUrl: string | undefined,
  filePath: string,
  lines: number[],
): string | undefined {
  if (!repoUrl) return undefined;
  const base = repoUrl.replace(/\/+$/, "").replace(/\/blob\/[^/]+$/, "");
  const firstLine = lines[0];
  const lastLine = lines[lines.length - 1];
  const anchor = firstLine === lastLine ? `#L${firstLine}` : `#L${firstLine}-L${lastLine}`;
  const branch = repoUrl.match(/\/blob\/([^/]+)/)?.[1] ?? "main";
  return `${base}/blob/${branch}/${filePath}${anchor}`;
}

function buildDescription(
  finding: Finding,
  record: FileRecord,
  projectId: string,
  owners: OwnerSummary,
  githubUrl?: string,
): string {
  const head = githubUrl
    ? `**File:** [\`${record.filePath}\`](${githubUrl}) (lines ${finding.lineNumbers.join(", ")})`
    : `**File:** \`${record.filePath}\` (lines ${finding.lineNumbers.join(", ")})`;

  const parts: string[] = [
    head,
    `**Project:** ${projectId}`,
    `**Severity:** ${finding.severity}  •  **Confidence:** ${finding.confidence}  •  **Slug:** \`${finding.vulnSlug}\``,
  ];

  if (owners.assignee || owners.teams.length > 0 || owners.oncall.length > 0) {
    parts.push("", "## Owners");
    if (owners.assignee) {
      parts.push(
        "",
        `**Suggested assignee:** \`${owners.assignee}\` _(via ${owners.assigneeSource})_`,
      );
    }
    if (owners.teams.length > 0) {
      parts.push(
        "",
        "**Teams:**",
        ...owners.teams.slice(0, 3).map((t) => `- ${t.name} (\`${t.slug}\`)`),
      );
    }
    if (owners.oncall.length > 0) {
      parts.push(
        "",
        "**Current on-call:**",
        ...owners.oncall.slice(0, 3).map((o) => {
          const gh = o.github_username
            ? ` • [@${o.github_username}](https://github.com/${o.github_username})`
            : "";
          return `- ${o.name} <${o.email}>${gh}`;
        }),
      );
    }
    if (owners.managers.length > 0) {
      parts.push("", "**Managers:**", ...owners.managers.slice(0, 3).map((m) => `- <${m.email}>`));
    }
  }

  parts.push(
    "",
    "## Finding",
    "",
    finding.description,
    "",
    "## Recommendation",
    "",
    finding.recommendation,
  );

  if (finding.revalidation) {
    parts.push(
      "",
      "## Revalidation",
      "",
      `**Verdict:** ${finding.revalidation.verdict}`,
      "",
      finding.revalidation.reasoning,
    );
  }

  if (owners.contributors.length > 0) {
    parts.push(
      "",
      "## Top contributors",
      "",
      ...owners.contributors.map((c) => `- ${c.name} <${c.email}> (score: ${c.score.toFixed(2)})`),
    );
  }
  if (owners.recentCommitters.length > 0) {
    parts.push(
      "",
      "## Recent committers (`git log`)",
      "",
      ...owners.recentCommitters.map((c) => `- ${c.name} <${c.email}> (${c.date.slice(0, 10)})`),
    );
  }

  return parts.join("\n");
}

function inDay(iso: string, dayStart: number, dayEnd: number): boolean {
  const t = Date.parse(iso);
  return !Number.isNaN(t) && t >= dayStart && t < dayEnd;
}

function startOfTodayLocal(): number {
  const d = new Date();
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}

function listProjectIds(): string[] {
  const dataDirPath = path.resolve(getDataRoot());
  if (!fs.existsSync(dataDirPath)) return [];
  return fs
    .readdirSync(dataDirPath, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .filter((p) => fs.existsSync(path.join(dataDirPath, p, "project.json")));
}

/** Stable, filesystem-safe filename for a finding in md-dir mode. */
function findingFilename(f: ExportedFinding): string {
  const hash = crypto
    .createHash("sha1")
    .update(
      `${f.metadata.projectId}\0${f.metadata.filePath}\0${f.metadata.lineNumbers.join(",")}\0${f.metadata.vulnSlug}`,
    )
    .digest("hex")
    .slice(0, 10);
  const safeSlug = f.metadata.vulnSlug.replace(/[^a-zA-Z0-9-]/g, "-");
  const safeProject = f.metadata.projectId.replace(/[^a-zA-Z0-9-]/g, "-");
  return `${safeProject}-${safeSlug}-${hash}.md`;
}

function writeJson(findings: ExportedFinding[], out: string | undefined) {
  const json = JSON.stringify(findings, null, 2);
  if (out) {
    fs.mkdirSync(path.dirname(path.resolve(out)), { recursive: true });
    fs.writeFileSync(out, json + "\n");
    console.log(`\n${GREEN}Exported ${findings.length} finding(s)${RESET} → ${BOLD}${out}${RESET}`);
  } else {
    process.stdout.write(json + "\n");
  }
}

function writeMdDir(findings: ExportedFinding[], out: string) {
  const root = path.resolve(out);
  fs.mkdirSync(root, { recursive: true });

  for (const f of findings) {
    const dir = path.join(root, f.metadata.severity);
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, findingFilename(f));
    const body = `# ${f.title}\n\n${f.description}\n`;
    fs.writeFileSync(file, body);
  }

  console.log(`\n${GREEN}Exported ${findings.length} finding(s)${RESET} → ${BOLD}${root}/${RESET}`);
}

export async function exportCommand(opts: {
  projectId?: string;
  minSeverity?: string;
  onlySeverity?: string;
  discoveredToday?: boolean;
  since?: string;
  onlyTruePositive?: boolean;
  excludeFalsePositive?: boolean;
  onlySlugs?: string;
  skipSlugs?: string;
  out?: string;
  format?: string;
  /** Drop findings without any ownership data (no assignee, no teams) */
  requireOwner?: boolean;
  /** Only include findings produced by this agent backend (e.g. `codex`) */
  onlyAgent?: string;
  /** Only include findings produced under this --reinvestigate wave marker */
  onlyMarker?: string;
}) {
  const projectIds = opts.projectId
    ? opts.projectId
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
    : listProjectIds();

  const format = opts.format ?? "json";
  if (format !== "json" && format !== "md-dir") {
    throw new Error(`--format must be "json" or "md-dir", got "${format}"`);
  }
  if (format === "md-dir" && !opts.out) {
    throw new Error(`--format md-dir requires --out <dir>`);
  }

  const minSeverity = opts.minSeverity as Severity | undefined;
  const onlySeverity = opts.onlySeverity as Severity | undefined;
  if (onlySeverity && !(onlySeverity in SEVERITY_ORDER)) {
    throw new Error(`--only-severity: not a valid severity: ${opts.onlySeverity}`);
  }

  let sinceMs: number | undefined;
  let untilMs = Number.POSITIVE_INFINITY;
  if (opts.discoveredToday) {
    sinceMs = startOfTodayLocal();
    untilMs = sinceMs + 24 * 60 * 60 * 1000;
  } else if (opts.since) {
    const t = Date.parse(opts.since);
    if (Number.isNaN(t)) throw new Error(`--since: not a valid ISO timestamp: ${opts.since}`);
    sinceMs = t;
  }

  const onlySlugs = opts.onlySlugs
    ?.split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const skipSlugs = opts.skipSlugs
    ?.split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const onlySlugSet = onlySlugs?.length ? new Set(onlySlugs) : undefined;
  const skipSlugSet = skipSlugs?.length ? new Set(skipSlugs) : undefined;

  console.log(`${BOLD}Exporting findings (${format})${RESET}`);
  console.log(`  Projects: ${projectIds.join(", ") || "(none)"}`);
  if (minSeverity) console.log(`  Min severity: ${minSeverity}`);
  if (onlySeverity) console.log(`  Only severity: ${onlySeverity}`);
  if (opts.discoveredToday) console.log(`  ${YELLOW}Filter: discovered today only${RESET}`);
  if (opts.since) console.log(`  Filter: discovered since ${opts.since}`);
  if (opts.onlyTruePositive) console.log(`  Filter: only revalidated true-positive`);
  if (opts.excludeFalsePositive) console.log(`  Filter: exclude revalidated false-positive`);
  if (onlySlugs) console.log(`  Only slugs: ${onlySlugs.join(", ")}`);
  if (skipSlugs) console.log(`  Skip slugs: ${skipSlugs.join(", ")}`);
  if (opts.requireOwner)
    console.log(`  ${YELLOW}Filter: only findings with ownership data${RESET}`);
  const onlyMarker = opts.onlyMarker !== undefined ? Number(opts.onlyMarker) : undefined;
  if (onlyMarker !== undefined && !Number.isFinite(onlyMarker)) {
    throw new Error(`--only-marker must be a number, got "${opts.onlyMarker}"`);
  }
  if (opts.onlyAgent) console.log(`  Only agent: ${opts.onlyAgent}`);
  if (onlyMarker !== undefined) console.log(`  Only marker: ${onlyMarker}`);

  const findings: ExportedFinding[] = [];
  let droppedNoOwner = 0;
  let withAssignee = 0;
  let withTeam = 0;

  for (const projectId of projectIds) {
    let records: FileRecord[];
    try {
      records = loadAllFileRecords(projectId);
    } catch (err) {
      console.error(
        `  ${DIM}[${projectId}] skipped: ${err instanceof Error ? err.message : err}${RESET}`,
      );
      continue;
    }
    const repoUrl = projectRepoUrl(projectId);
    let emitted = 0;

    for (const record of records) {
      const latest = record.analysisHistory?.[record.analysisHistory.length - 1];
      if (!latest) continue;

      if (sinceMs !== undefined && !inDay(latest.investigatedAt, sinceMs, untilMs)) continue;

      // Build a map: finding-index → analysisHistory entry that produced it.
      // Findings are appended in analysisHistory order, so the i-th finding
      // belongs to whichever entry's findingCount range covers i.
      const findingSource: Array<(typeof record.analysisHistory)[number] | undefined> = [];
      let cursor = 0;
      for (const h of record.analysisHistory ?? []) {
        const fc = h.findingCount ?? 0;
        for (let k = 0; k < fc; k++) findingSource[cursor++] = h;
      }

      let findingIndex = -1;
      for (const finding of record.findings ?? []) {
        findingIndex++;
        if (minSeverity && SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[minSeverity]) continue;
        if (onlySeverity && finding.severity !== onlySeverity) continue;
        if (onlySlugSet && !onlySlugSet.has(finding.vulnSlug)) continue;
        if (skipSlugSet?.has(finding.vulnSlug)) continue;
        if (opts.onlyTruePositive && finding.revalidation?.verdict !== "true-positive") continue;
        if (opts.excludeFalsePositive && finding.revalidation?.verdict === "false-positive")
          continue;

        const source = findingSource[findingIndex];
        if (opts.onlyAgent && source?.agentType !== opts.onlyAgent) continue;
        if (onlyMarker !== undefined && source?.reinvestigateMarker !== onlyMarker) continue;

        const githubUrl = makeGithubLink(repoUrl, record.filePath, finding.lineNumbers);
        const owners = summarizeOwners(record);

        const hasOwner = !!owners.assignee || owners.teams.length > 0 || owners.oncall.length > 0;
        if (opts.requireOwner && !hasOwner) {
          droppedNoOwner++;
          continue;
        }

        const labels = [
          "security",
          `project:${projectId}`,
          `severity:${finding.severity}`,
          `slug:${finding.vulnSlug}`,
          `confidence:${finding.confidence}`,
        ];
        if (finding.revalidation?.verdict)
          labels.push(`revalidation:${finding.revalidation.verdict}`);
        for (const t of owners.teams.slice(0, 3)) labels.push(`owning-team:${t.slug}`);
        if (!hasOwner) labels.push("missing-owner");

        if (owners.assignee) withAssignee++;
        if (owners.teams.length > 0) withTeam++;

        findings.push({
          title: `[${finding.severity}] ${finding.title}`,
          description: buildDescription(finding, record, projectId, owners, githubUrl),
          severity: finding.severity,
          labels,
          assignee: owners.assignee,
          metadata: {
            projectId,
            filePath: record.filePath,
            lineNumbers: finding.lineNumbers,
            severity: finding.severity,
            vulnSlug: finding.vulnSlug,
            confidence: finding.confidence,
            discoveredAt: latest.investigatedAt,
            runId: latest.runId,
            revalidation: finding.revalidation
              ? { verdict: finding.revalidation.verdict, reasoning: finding.revalidation.reasoning }
              : undefined,
            githubUrl,
            owners,
          },
        });
        emitted++;
      }
    }
    console.log(`  [${projectId}] ${emitted} finding(s)`);
  }

  // Sort: severity ascending (CRITICAL first), then project, then file
  findings.sort((a, b) => {
    const sa = SEVERITY_ORDER[a.metadata.severity];
    const sb = SEVERITY_ORDER[b.metadata.severity];
    if (sa !== sb) return sa - sb;
    if (a.metadata.projectId !== b.metadata.projectId)
      return a.metadata.projectId.localeCompare(b.metadata.projectId);
    return a.metadata.filePath.localeCompare(b.metadata.filePath);
  });

  if (format === "md-dir") {
    writeMdDir(findings, opts.out!);
  } else {
    writeJson(findings, opts.out);
  }

  if (findings.length > 0) {
    const pct = (n: number) => `${((n / findings.length) * 100).toFixed(0)}%`;
    console.log();
    console.log(`${BOLD}Ownership coverage:${RESET}`);
    console.log(`  with assignee:    ${withAssignee}/${findings.length} (${pct(withAssignee)})`);
    console.log(`  with owning team: ${withTeam}/${findings.length} (${pct(withTeam)})`);
    if (droppedNoOwner > 0) {
      console.log(`  ${YELLOW}dropped (--require-owner): ${droppedNoOwner}${RESET}`);
    }
  }
}

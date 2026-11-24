import { execFileSync } from "node:child_process";
import type { Severity } from "@deepsec/core";
import type { ExportedFinding } from "./export.js";

const SARIF_LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  CRITICAL: "error",
  HIGH: "error",
  HIGH_BUG: "warning",
  MEDIUM: "warning",
  BUG: "warning",
  LOW: "note",
};

// GitHub code scanning ranks security alerts by `security-severity` and
// other alerts by `problem.severity`.
const SECURITY_SEVERITY: Partial<Record<Severity, string>> = {
  CRITICAL: "9.5",
  HIGH: "8.0",
  MEDIUM: "5.0",
  LOW: "2.0",
};

const PROBLEM_SEVERITY: Partial<Record<Severity, string>> = {
  HIGH_BUG: "error",
  BUG: "warning",
};

function titleWithoutSeverity(title: string): string {
  return title.replace(/^\[[^\]]+\]\s*/, "");
}

/**
 * The project root's path inside its git repository (`apps/web/`), or ""
 * when it is the repository root or not in a git checkout. GitHub resolves
 * SARIF paths from the repository root.
 */
export function repoPathPrefix(rootPath: string): string {
  try {
    return execFileSync("git", ["rev-parse", "--show-prefix"], {
      cwd: rootPath,
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 5000,
    }).trim();
  } catch {
    return "";
  }
}

function physicalLocation(filePath: string, line?: number) {
  const uri = filePath
    .replaceAll("\\", "/")
    .split("/")
    .map((part) => encodeURIComponent(part))
    .join("/");
  return {
    artifactLocation: { uri },
    ...(line !== undefined ? { region: { startLine: line } } : {}),
  };
}

// GitHub reads severity from the rule, not the result, so each rule covers
// one slug at one severity. Ids are `<slug>/<severity>`, e.g.
// `sql-injection/high`, so they stay stable across exports.
function ruleId(finding: ExportedFinding): string {
  return `${finding.metadata.vulnSlug}/${finding.severity.toLowerCase()}`;
}

/**
 * Convert exported findings to a SARIF 2.1.0 log, prefixing file paths with
 * `pathPrefix`. Code scanning alerts are readable by anyone with alert
 * access, so ownership labels and `assignee` are dropped, and each
 * `description` must already be built without owner details.
 */
export function toSarif(findings: ExportedFinding[], version: string, pathPrefix = "") {
  const ruleKeys = new Map<string, { slug: string; severity: Severity }>();
  for (const f of findings) {
    ruleKeys.set(ruleId(f), { slug: f.metadata.vulnSlug, severity: f.severity });
  }
  const ruleIds = [...ruleKeys.keys()].sort();
  const ruleIndexes = new Map(ruleIds.map((id, i) => [id, i]));
  const rules = ruleIds.map((id) => {
    const { slug, severity } = ruleKeys.get(id)!;
    const securitySeverity = SECURITY_SEVERITY[severity];
    const problemSeverity = PROBLEM_SEVERITY[severity];
    return {
      id,
      shortDescription: { text: `${slug} (${severity})` },
      defaultConfiguration: { level: SARIF_LEVEL[severity] },
      properties: {
        tags: [securitySeverity ? "security" : "correctness"],
        ...(securitySeverity ? { "security-severity": securitySeverity } : {}),
        ...(problemSeverity ? { "problem.severity": problemSeverity } : {}),
        "deepsec/severity": severity,
      },
    };
  });

  const results = findings.map((finding) => {
    const { metadata } = finding;
    const lines = [...new Set(metadata.lineNumbers.filter((n) => Number.isInteger(n) && n > 0))];
    lines.sort((a, b) => a - b);
    const filePath = pathPrefix + metadata.filePath;
    const id = ruleId(finding);
    return {
      ruleId: id,
      ruleIndex: ruleIndexes.get(id),
      level: SARIF_LEVEL[finding.severity],
      message: { text: titleWithoutSeverity(finding.title), markdown: finding.description },
      locations: [{ physicalLocation: physicalLocation(filePath, lines[0]) }],
      ...(lines.length > 1
        ? {
            relatedLocations: lines.slice(1).map((line, i) => ({
              id: i + 1,
              physicalLocation: physicalLocation(filePath, line),
            })),
          }
        : {}),
      ...(metadata.findingId
        ? { partialFingerprints: { "deepsecFindingId/v1": metadata.findingId } }
        : {}),
      properties: {
        tags: [
          SECURITY_SEVERITY[finding.severity] ? "security" : "correctness",
          ...finding.labels.filter(
            (label) =>
              label !== "security" &&
              label !== "missing-owner" &&
              !label.startsWith("owning-team:"),
          ),
        ],
        "deepsec/projectId": metadata.projectId,
        "deepsec/severity": finding.severity,
        "deepsec/confidence": metadata.confidence,
        "deepsec/discoveredAt": metadata.discoveredAt,
        "deepsec/runId": metadata.runId,
        ...(metadata.githubUrl ? { "deepsec/githubUrl": metadata.githubUrl } : {}),
        ...(metadata.revalidation
          ? { "deepsec/revalidationVerdict": metadata.revalidation.verdict }
          : {}),
      },
    };
  });

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "deepsec",
            semanticVersion: version,
            informationUri: "https://github.com/vercel-labs/deepsec",
            rules,
          },
        },
        results,
      },
    ],
  };
}

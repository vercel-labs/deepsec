import crypto from "node:crypto";

type Severity = "CRITICAL" | "HIGH" | "HIGH_BUG" | "MEDIUM" | "BUG" | "LOW";

interface SarifFinding {
  title: string;
  description: string;
  severity: Severity;
  labels: string[];
  assignee?: string;
  metadata: {
    projectId: string;
    filePath: string;
    lineNumbers: number[];
    vulnSlug: string;
    confidence: string;
    discoveredAt: string;
    runId: string;
    revalidation?: { verdict: string };
    githubUrl?: string;
  };
}

type SarifLevel = "error" | "warning" | "note";

const SARIF_LEVEL: Record<Severity, SarifLevel> = {
  CRITICAL: "error",
  HIGH: "error",
  HIGH_BUG: "warning",
  MEDIUM: "warning",
  BUG: "warning",
  LOW: "note",
};

const SECURITY_SEVERITY: Partial<Record<Severity, string>> = {
  CRITICAL: "9.5",
  HIGH: "8.0",
  MEDIUM: "5.0",
  LOW: "2.0",
};

const PROBLEM_SEVERITY: Partial<Record<Severity, "error" | "warning">> = {
  HIGH_BUG: "error",
  BUG: "warning",
};

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  HIGH_BUG: 2,
  MEDIUM: 3,
  BUG: 4,
  LOW: 5,
};

function titleWithoutSeverity(title: string): string {
  return title.replace(/^\[[^\]]+\]\s*/, "");
}

function artifactUri(filePath: string): string {
  return filePath
    .replaceAll("\\", "/")
    .split("/")
    .map((part) => encodeURIComponent(part))
    .join("/");
}

function fingerprint(finding: SarifFinding): string {
  return crypto
    .createHash("sha256")
    .update(
      `${finding.metadata.projectId}\0${finding.metadata.filePath.replaceAll("\\", "/")}\0${finding.metadata.vulnSlug}\0${titleWithoutSeverity(finding.title).trim().toLowerCase()}`,
    )
    .digest("hex");
}

function resultTags(finding: SarifFinding): string[] {
  const classification = SECURITY_SEVERITY[finding.severity] ? "security" : "correctness";
  return [
    classification,
    ...finding.labels.filter((tag) => tag !== "security" && tag !== "correctness"),
  ];
}

function sourceLines(finding: SarifFinding): number[] {
  return [
    ...new Set(finding.metadata.lineNumbers.filter((line) => Number.isInteger(line) && line > 0)),
  ].sort((a, b) => a - b);
}

function physicalLocation(finding: SarifFinding, line?: number) {
  return {
    artifactLocation: {
      uri: artifactUri(finding.metadata.filePath),
    },
    ...(line !== undefined
      ? {
          region: {
            startLine: line,
          },
        }
      : {}),
  };
}

export function toSarif(findings: SarifFinding[], version: string) {
  const ruleFindings = new Map<string, SarifFinding[]>();
  for (const finding of findings) {
    const existing = ruleFindings.get(finding.metadata.vulnSlug) ?? [];
    existing.push(finding);
    ruleFindings.set(finding.metadata.vulnSlug, existing);
  }

  const ruleIds = [...ruleFindings.keys()].sort();
  const ruleIndexes = new Map(ruleIds.map((ruleId, index) => [ruleId, index]));
  const rules = ruleIds.map((ruleId) => {
    const matches = ruleFindings.get(ruleId)!;
    const representative = [...matches].sort((a, b) => {
      const severityDifference = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
      if (severityDifference !== 0) return severityDifference;
      return a.title.localeCompare(b.title);
    })[0]!;
    const securitySeverity = SECURITY_SEVERITY[representative.severity];
    const problemSeverity = PROBLEM_SEVERITY[representative.severity];

    return {
      id: ruleId,
      shortDescription: { text: titleWithoutSeverity(representative.title) },
      defaultConfiguration: { level: SARIF_LEVEL[representative.severity] },
      properties: {
        tags: [securitySeverity ? "security" : "correctness"],
        ...(securitySeverity ? { "security-severity": securitySeverity } : {}),
        ...(problemSeverity ? { "problem.severity": problemSeverity } : {}),
        "deepsec/severity": representative.severity,
      },
    };
  });

  const results = findings.map((finding) => {
    const lines = sourceLines(finding);
    return {
      ruleId: finding.metadata.vulnSlug,
      ruleIndex: ruleIndexes.get(finding.metadata.vulnSlug)!,
      level: SARIF_LEVEL[finding.severity],
      message: {
        text: titleWithoutSeverity(finding.title),
        markdown: finding.description,
      },
      locations: [{ physicalLocation: physicalLocation(finding, lines[0]) }],
      ...(lines.length > 1
        ? {
            relatedLocations: lines.slice(1).map((line, index) => ({
              id: index + 1,
              physicalLocation: physicalLocation(finding, line),
            })),
          }
        : {}),
      partialFingerprints: {
        "deepsecFindingId/v1": fingerprint(finding),
      },
      properties: {
        tags: resultTags(finding),
        "deepsec/projectId": finding.metadata.projectId,
        "deepsec/severity": finding.severity,
        "deepsec/confidence": finding.metadata.confidence,
        "deepsec/discoveredAt": finding.metadata.discoveredAt,
        "deepsec/runId": finding.metadata.runId,
        ...(finding.assignee ? { "deepsec/assignee": finding.assignee } : {}),
        ...(finding.metadata.githubUrl ? { "deepsec/githubUrl": finding.metadata.githubUrl } : {}),
        ...(finding.metadata.revalidation
          ? { "deepsec/revalidationVerdict": finding.metadata.revalidation.verdict }
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

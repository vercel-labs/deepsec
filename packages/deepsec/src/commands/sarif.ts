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

function physicalLocation(finding: SarifFinding) {
  const lines = finding.metadata.lineNumbers.filter((line) => Number.isInteger(line) && line > 0);
  const startLine = lines.length > 0 ? Math.min(...lines) : undefined;
  const endLine = lines.length > 0 ? Math.max(...lines) : undefined;

  return {
    artifactLocation: {
      uri: artifactUri(finding.metadata.filePath),
      uriBaseId: "%SRCROOT%",
    },
    ...(startLine !== undefined
      ? {
          region: {
            startLine,
            ...(endLine !== startLine ? { endLine } : {}),
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

    return {
      id: ruleId,
      shortDescription: { text: titleWithoutSeverity(representative.title) },
      defaultConfiguration: { level: SARIF_LEVEL[representative.severity] },
      properties: {
        tags: ["security"],
        "deepsec/severity": representative.severity,
      },
    };
  });

  const results = findings.map((finding) => ({
    ruleId: finding.metadata.vulnSlug,
    ruleIndex: ruleIndexes.get(finding.metadata.vulnSlug)!,
    level: SARIF_LEVEL[finding.severity],
    message: {
      text: titleWithoutSeverity(finding.title),
      markdown: finding.description,
    },
    locations: [{ physicalLocation: physicalLocation(finding) }],
    partialFingerprints: {
      "deepsecFindingId/v1": fingerprint(finding),
    },
    properties: {
      tags: finding.labels,
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
  }));

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

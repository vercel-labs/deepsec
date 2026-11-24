import type { FileRecord } from "@deepsec/core";

export function summarizeProcessRecords(records: FileRecord[], errorBatchCount: number) {
  const findings = records.flatMap((record) => record.findings);
  const history = records.flatMap((record) =>
    record.analysisHistory.filter((entry) => entry.phase !== "revalidate"),
  );
  const findingsBySeverity = Object.fromEntries(
    findings.reduce((counts, finding) => {
      counts.set(finding.severity, (counts.get(finding.severity) ?? 0) + 1);
      return counts;
    }, new Map<string, number>()),
  );
  return {
    analysisCount: records.filter((record) => record.status === "analyzed").length,
    findingCount: findings.length,
    errorBatchCount,
    findingsBySeverity,
    costUsd: history.reduce((total, entry) => total + (entry.costUsd ?? 0), 0),
  };
}

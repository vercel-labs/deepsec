import { describe, expect, it } from "vitest";
import type { ExportedFinding } from "../commands/export.js";
import { toSarif } from "../commands/sarif.js";

function finding(overrides: Partial<ExportedFinding> = {}): ExportedFinding {
  return {
    title: "[HIGH] SQL injection",
    description: "Untrusted input reaches a database query.",
    severity: "HIGH",
    labels: ["security", "slug:sql-injection"],
    metadata: {
      projectId: "web",
      filePath: "src/user search.ts",
      lineNumbers: [15, 12, 15],
      severity: "HIGH",
      vulnSlug: "sql-injection",
      confidence: "high",
      discoveredAt: "2026-07-18T12:00:00.000Z",
      runId: "run-1",
      owners: {
        teams: [],
        oncall: [],
        managers: [],
        contributors: [],
        recentCommitters: [],
      },
    },
    ...overrides,
  };
}

describe("toSarif", () => {
  it("emits SARIF 2.1.0 rules, results, and source locations", () => {
    const sarif = toSarif([finding()], "2.2.3");
    const run = sarif.runs[0];
    const rule = run.tool.driver.rules[0];
    const result = run.results[0];

    expect(sarif.$schema).toBe("https://json.schemastore.org/sarif-2.1.0.json");
    expect(sarif.version).toBe("2.1.0");
    expect(run.tool.driver).toMatchObject({ name: "deepsec", semanticVersion: "2.2.3" });
    expect(rule).toMatchObject({
      id: "sql-injection",
      shortDescription: { text: "SQL injection" },
      defaultConfiguration: { level: "error" },
    });
    expect(result).toMatchObject({
      ruleId: "sql-injection",
      ruleIndex: 0,
      level: "error",
      message: { text: "SQL injection" },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: "src/user%20search.ts" },
            region: { startLine: 12, endLine: 15 },
          },
        },
      ],
    });
  });

  it("deduplicates and sorts rules while preserving result rule indexes", () => {
    const commandInjection = finding({
      title: "[LOW] Command injection",
      severity: "LOW",
      metadata: {
        ...finding().metadata,
        vulnSlug: "command-injection",
        severity: "LOW",
      },
    });
    const sarif = toSarif([finding(), commandInjection, finding()], "2.2.3");
    const run = sarif.runs[0];

    expect(run.tool.driver.rules.map((rule) => rule.id)).toEqual([
      "command-injection",
      "sql-injection",
    ]);
    expect(run.results.map((result) => result.ruleIndex)).toEqual([1, 0, 1]);
  });

  it.each([
    ["CRITICAL", "error"],
    ["HIGH", "error"],
    ["HIGH_BUG", "warning"],
    ["MEDIUM", "warning"],
    ["BUG", "warning"],
    ["LOW", "note"],
  ] as const)("maps %s findings to the %s SARIF level", (severity, level) => {
    const input = finding({
      severity,
      metadata: { ...finding().metadata, severity },
    });
    expect(toSarif([input], "2.2.3").runs[0].results[0].level).toBe(level);
  });

  it("produces deterministic fingerprints from finding identity", () => {
    const original = toSarif([finding()], "2.2.3").runs[0].results[0].partialFingerprints;
    const reorderedLines = finding({
      metadata: { ...finding().metadata, lineNumbers: [12, 15] },
    });
    const reordered = toSarif([reorderedLines], "2.2.3").runs[0].results[0].partialFingerprints;
    const moved = finding({ metadata: { ...finding().metadata, lineNumbers: [16] } });
    const movedFingerprint = toSarif([moved], "2.2.3").runs[0].results[0].partialFingerprints;
    const differentTitle = finding({ title: "[HIGH] Second SQL injection" });
    const differentTitleFingerprint = toSarif([differentTitle], "2.2.3").runs[0].results[0]
      .partialFingerprints;

    expect(original).toEqual(reordered);
    expect(original["deepsecFindingId/v1"]).toMatch(/^[a-f0-9]{64}$/);
    expect(movedFingerprint).toEqual(original);
    expect(differentTitleFingerprint).not.toEqual(original);
  });
});

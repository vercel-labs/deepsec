import type { Severity } from "@deepsec/core";
import { describe, expect, it } from "vitest";
import { buildSarifLog } from "../commands/export.js";

/**
 * Minimal ExportedFinding factory for testing. The full ExportedFinding
 * interface is large; we fill only the fields buildSarifLog reads, plus
 * stubs for the rest to satisfy the type.
 */
function makeFinding(overrides: {
  projectId?: string;
  filePath?: string;
  lineNumbers?: number[];
  severity?: Severity;
  vulnSlug?: string;
  confidence?: string;
  title?: string;
  description?: string;
  revalidation?: { verdict: string; reasoning: string };
}): import("../commands/export.js").ExportedFinding {
  return {
    title: overrides.title ?? `[${overrides.severity ?? "HIGH"}] Test finding`,
    description: overrides.description ?? "Test description",
    severity: overrides.severity ?? "HIGH",
    labels: [],
    metadata: {
      projectId: overrides.projectId ?? "my-app",
      filePath: overrides.filePath ?? "src/api/users.ts",
      lineNumbers: overrides.lineNumbers ?? [42],
      severity: overrides.severity ?? "HIGH",
      vulnSlug: overrides.vulnSlug ?? "sql-injection",
      confidence: overrides.confidence ?? "high",
      discoveredAt: "2026-07-29T00:00:00.000Z",
      runId: "run-1",
      revalidation: overrides.revalidation,
      owners: {
        teams: [],
        oncall: [],
        managers: [],
        contributors: [],
        recentCommitters: [],
      },
    },
  };
}

describe("buildSarifLog()", () => {
  it("produces a valid SARIF 2.1.0 top-level structure", () => {
    const log = buildSarifLog([makeFinding({})]);

    expect(log.$schema).toBe("https://json.schemastore.org/sarif-2.1.0.json");
    expect(log.version).toBe("2.1.0");
    expect(Array.isArray(log.runs)).toBe(true);
    expect(log.runs.length).toBe(1);
  });

  it("sets tool driver metadata correctly", () => {
    const log = buildSarifLog([makeFinding({})]);
    const driver = log.runs[0].tool.driver;

    expect(driver.name).toBe("deepsec");
    expect(typeof driver.version).toBe("string");
    expect(driver.version.length).toBeGreaterThan(0);
    expect(driver.informationUri).toBe("https://deepsec.sh");
  });

  it("maps severity to SARIF level correctly", () => {
    const cases: Array<{ severity: Severity; level: string }> = [
      { severity: "CRITICAL", level: "error" },
      { severity: "HIGH", level: "error" },
      { severity: "HIGH_BUG", level: "warning" },
      { severity: "MEDIUM", level: "warning" },
      { severity: "BUG", level: "note" },
      { severity: "LOW", level: "note" },
    ];

    for (const { severity, level } of cases) {
      const log = buildSarifLog([makeFinding({ severity })]);
      expect(log.runs[0].results[0].level, `severity ${severity}`).toBe(level);
    }
  });

  it("deduplicates rules by vulnSlug within a run", () => {
    const findings = [
      makeFinding({ vulnSlug: "sql-injection", filePath: "a.ts", lineNumbers: [1] }),
      makeFinding({ vulnSlug: "sql-injection", filePath: "b.ts", lineNumbers: [5] }),
      makeFinding({ vulnSlug: "xss", filePath: "c.ts", lineNumbers: [10] }),
    ];

    const log = buildSarifLog(findings);
    const rules = log.runs[0].tool.driver.rules;

    expect(rules.length).toBe(2);
    expect(rules.map((r) => r.id).sort()).toEqual(["sql-injection", "xss"]);
  });

  it("sets location with startLine and endLine for multi-line findings", () => {
    const log = buildSarifLog([makeFinding({ lineNumbers: [10, 11, 12] })]);
    const region = log.runs[0].results[0].locations[0].physicalLocation.region;

    expect(region.startLine).toBe(10);
    expect(region.endLine).toBe(12);
  });

  it("sets location with startLine only for single-line findings", () => {
    const log = buildSarifLog([makeFinding({ lineNumbers: [42] })]);
    const region = log.runs[0].results[0].locations[0].physicalLocation.region;

    expect(region.startLine).toBe(42);
    expect(region.endLine).toBeUndefined();
  });

  it("uses relative file path as artifact URI", () => {
    const log = buildSarifLog([makeFinding({ filePath: "src/lib/auth.ts" })]);
    const uri = log.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;

    expect(uri).toBe("src/lib/auth.ts");
  });

  it("produces stable partialFingerprints across calls", () => {
    const finding = makeFinding({ filePath: "src/a.ts", lineNumbers: [7] });
    const log1 = buildSarifLog([finding]);
    const log2 = buildSarifLog([finding]);

    const fp1 = log1.runs[0].results[0].partialFingerprints.primaryLocationLineHash;
    const fp2 = log2.runs[0].results[0].partialFingerprints.primaryLocationLineHash;

    expect(fp1).toBe(fp2);
    expect(fp1.length).toBe(32);
  });

  it("produces different fingerprints for different files", () => {
    const log = buildSarifLog([
      makeFinding({ filePath: "src/a.ts", lineNumbers: [1] }),
      makeFinding({ filePath: "src/b.ts", lineNumbers: [1] }),
    ]);

    const fp1 = log.runs[0].results[0].partialFingerprints.primaryLocationLineHash;
    const fp2 = log.runs[0].results[1].partialFingerprints.primaryLocationLineHash;

    expect(fp1).not.toBe(fp2);
  });

  it("preserves original severity in result.properties", () => {
    const log = buildSarifLog([makeFinding({ severity: "CRITICAL" })]);
    const props = log.runs[0].results[0].properties;

    expect(props["deepsec-severity"]).toBe("CRITICAL");
    expect(props["deepsec-confidence"]).toBe("high");
    expect(props["deepsec-vuln-slug"]).toBe("sql-injection");
    expect(props["deepsec-project-id"]).toBe("my-app");
  });

  it("includes revalidation verdict in properties when present", () => {
    const log = buildSarifLog([
      makeFinding({ revalidation: { verdict: "true-positive", reasoning: "confirmed" } }),
    ]);
    const props = log.runs[0].results[0].properties;

    expect(props["deepsec-revalidation"]).toBe("true-positive");
  });

  it("omits revalidation property when not present", () => {
    const log = buildSarifLog([makeFinding({})]);
    const props = log.runs[0].results[0].properties;

    expect(props["deepsec-revalidation"]).toBeUndefined();
  });

  it("creates one run per project", () => {
    const findings = [
      makeFinding({ projectId: "app-a", filePath: "a.ts" }),
      makeFinding({ projectId: "app-b", filePath: "b.ts" }),
      makeFinding({ projectId: "app-a", filePath: "c.ts" }),
    ];

    const log = buildSarifLog(findings);

    expect(log.runs.length).toBe(2);
    const projectIds = log.runs.map((r) => r.properties?.["deepsec-project-id"]).sort();
    expect(projectIds).toEqual(["app-a", "app-b"]);
  });

  it("produces valid empty SARIF when no findings", () => {
    const log = buildSarifLog([]);

    expect(log.version).toBe("2.1.0");
    expect(log.runs).toEqual([]);
  });

  it("humanizes vulnSlug for rule name", () => {
    const log = buildSarifLog([makeFinding({ vulnSlug: "sql-injection" })]);
    const rule = log.runs[0].tool.driver.rules[0];

    expect(rule.id).toBe("sql-injection");
    expect(rule.name).toBe("Sql Injection");
  });

  it("sets ruleId on each result matching the rule id", () => {
    const log = buildSarifLog([
      makeFinding({ vulnSlug: "xss", filePath: "a.ts" }),
      makeFinding({ vulnSlug: "ssrf", filePath: "b.ts" }),
    ]);

    expect(log.runs[0].results[0].ruleId).toBe("xss");
    expect(log.runs[0].results[1].ruleId).toBe("ssrf");
  });

  it("uses finding description as result message text", () => {
    const log = buildSarifLog([makeFinding({ description: "Critical vuln here" })]);

    expect(log.runs[0].results[0].message.text).toBe("Critical vuln here");
  });
});

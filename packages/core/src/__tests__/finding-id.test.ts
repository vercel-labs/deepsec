import { describe, expect, it } from "vitest";
import { computeFindingId, ensureFindingIds } from "../finding-id.js";
import type { FileRecord, Finding } from "../types.js";

function finding(title: string, overrides: Partial<Finding> = {}): Finding {
  return {
    severity: "HIGH",
    vulnSlug: "auth-bypass",
    title,
    description: "d",
    lineNumbers: [1],
    recommendation: "r",
    confidence: "high",
    ...overrides,
  };
}

function record(findings: Finding[]): FileRecord {
  return {
    filePath: "src/app.ts",
    projectId: "proj",
    candidates: [],
    lastScannedAt: "",
    lastScannedRunId: "",
    fileHash: "",
    findings,
    analysisHistory: [],
    status: "analyzed",
  };
}

describe("computeFindingId", () => {
  it("is deterministic and shaped finding_<16 hex>", () => {
    const a = computeFindingId("proj", "src/app.ts", "SQL injection");
    expect(a).toMatch(/^finding_[0-9a-f]{16}$/);
    expect(computeFindingId("proj", "src/app.ts", "SQL injection")).toBe(a);
  });

  it("normalizes path separators and leading ./ so the same finding hashes equal", () => {
    const base = computeFindingId("proj", "src/app.ts", "t");
    expect(computeFindingId("proj", "./src/app.ts", "t")).toBe(base);
    expect(computeFindingId("proj", "src\\app.ts", "t")).toBe(base);
  });

  it("varies with projectId, filePath, and title only", () => {
    const base = computeFindingId("proj", "src/app.ts", "t");
    expect(computeFindingId("other", "src/app.ts", "t")).not.toBe(base);
    expect(computeFindingId("proj", "src/other.ts", "t")).not.toBe(base);
    expect(computeFindingId("proj", "src/app.ts", "u")).not.toBe(base);
  });
});

describe("ensureFindingIds", () => {
  it("backfills missing IDs and reports change", () => {
    const rec = record([finding("a"), finding("b")]);
    expect(ensureFindingIds(rec)).toBe(true);
    expect(rec.findings[0].findingId).toMatch(/^finding_/);
    expect(rec.findings[1].findingId).toMatch(/^finding_/);
    expect(rec.findings[0].findingId).not.toBe(rec.findings[1].findingId);
  });

  it("is a no-op when IDs are already present", () => {
    const rec = record([finding("a")]);
    ensureFindingIds(rec);
    const id = rec.findings[0].findingId;
    expect(ensureFindingIds(rec)).toBe(false);
    expect(rec.findings[0].findingId).toBe(id);
  });

  it("is stable across repeated loads (same derivation every time)", () => {
    const rec1 = record([finding("a"), finding("a")]);
    const rec2 = record([finding("a"), finding("a")]);
    ensureFindingIds(rec1);
    ensureFindingIds(rec2);
    expect(rec1.findings.map((f) => f.findingId)).toEqual(rec2.findings.map((f) => f.findingId));
  });

  it("disambiguates same-file title collisions with unique IDs", () => {
    const rec = record([finding("dup title"), finding("dup title", { vulnSlug: "xss" })]);
    ensureFindingIds(rec);
    const [a, b] = rec.findings.map((f) => f.findingId);
    expect(a).not.toBe(b);
  });

  it("never derives from mutable fields (severity/revalidation changes keep the ID)", () => {
    const rec = record([finding("a")]);
    ensureFindingIds(rec);
    const id = rec.findings[0].findingId;
    rec.findings[0].severity = "LOW";
    rec.findings[0].findingId = undefined;
    ensureFindingIds(rec);
    expect(rec.findings[0].findingId).toBe(id);
  });
});

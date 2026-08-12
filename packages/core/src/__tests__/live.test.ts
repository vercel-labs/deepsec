import { describe, expect, it } from "vitest";
import {
  digestScopeManifest,
  effectiveSeverity,
  type LiveScopeManifest,
  liveScopeManifestSchema,
  liveTargetProfileSchema,
  selectFindingsForVerify,
  severityAtLeast,
} from "../live.js";
import type { Finding } from "../types.js";

function finding(overrides: Partial<Finding>): Finding {
  return {
    findingId: "finding_x",
    severity: "HIGH",
    vulnSlug: "xss",
    title: "t",
    description: "d",
    lineNumbers: [1],
    recommendation: "r",
    confidence: "high",
    ...overrides,
  };
}

describe("effectiveSeverity / severityAtLeast", () => {
  it("uses the revalidation-adjusted severity when present", () => {
    const f = finding({
      severity: "HIGH",
      revalidation: {
        verdict: "true-positive",
        reasoning: "",
        adjustedSeverity: "CRITICAL",
        revalidatedAt: "2026-01-01",
        runId: "r1",
        model: "m",
      },
    });
    expect(effectiveSeverity(f)).toBe("CRITICAL");
  });

  it("falls back to the recorded severity without revalidation", () => {
    expect(effectiveSeverity(finding({ severity: "MEDIUM" }))).toBe("MEDIUM");
  });

  it("orders severity correctly", () => {
    expect(severityAtLeast("CRITICAL", "HIGH")).toBe(true);
    expect(severityAtLeast("HIGH", "HIGH")).toBe(true);
    expect(severityAtLeast("MEDIUM", "HIGH")).toBe(false);
  });
});

describe("selectFindingsForVerify", () => {
  const tp = {
    verdict: "true-positive" as const,
    reasoning: "",
    revalidatedAt: "2026-01-01",
    runId: "r1",
    model: "m",
  };

  it("selects true-positive findings at or above the bar", () => {
    const findings = [
      finding({ findingId: "a", severity: "HIGH", revalidation: tp }),
      finding({ findingId: "b", severity: "LOW", revalidation: tp }),
    ];
    const selected = selectFindingsForVerify(findings, { minSeverity: "HIGH" });
    expect(selected.map((f) => f.findingId)).toEqual(["a"]);
  });

  it("includes uncertain by default and excludes unrevalidated unless asked", () => {
    const findings = [
      finding({ findingId: "u", severity: "HIGH", revalidation: { ...tp, verdict: "uncertain" } }),
      finding({ findingId: "n", severity: "HIGH" }),
    ];
    expect(selectFindingsForVerify(findings).map((f) => f.findingId)).toEqual(["u"]);
    expect(
      selectFindingsForVerify(findings, { includeUnrevalidated: true }).map((f) => f.findingId),
    ).toEqual(["u", "n"]);
  });

  it("never selects fixed / false-positive / accepted-risk / duplicate", () => {
    const mk = (verdict: "fixed" | "false-positive" | "accepted-risk" | "duplicate") =>
      finding({ findingId: verdict, severity: "CRITICAL", revalidation: { ...tp, verdict } });
    const selected = selectFindingsForVerify(
      [mk("fixed"), mk("false-positive"), mk("accepted-risk"), mk("duplicate")],
      { minSeverity: "LOW" },
    );
    expect(selected).toEqual([]);
  });

  it("respects the effective (adjusted) severity, not the recorded one", () => {
    const downgraded = finding({
      findingId: "d",
      severity: "CRITICAL",
      revalidation: { ...tp, adjustedSeverity: "LOW" },
    });
    expect(selectFindingsForVerify([downgraded], { minSeverity: "HIGH" })).toEqual([]);
  });

  it("filters to requested finding IDs", () => {
    const findings = [
      finding({ findingId: "a", severity: "HIGH", revalidation: tp }),
      finding({ findingId: "b", severity: "HIGH", revalidation: tp }),
    ];
    expect(
      selectFindingsForVerify(findings, { findingIds: ["b"] }).map((f) => f.findingId),
    ).toEqual(["b"]);
  });
});

describe("digestScopeManifest", () => {
  const base: LiveScopeManifest = {
    projectId: "p",
    targetId: "t",
    baseUrl: "https://staging.example.com",
    allowedOrigins: ["https://staging.example.com"],
    selectedFindingIds: ["a", "b"],
    selectedRoutes: [],
    allowedMethods: ["GET"],
    allowedPathPrefixes: ["/"],
    identities: [],
    limits: {
      maxRequestsPerUnit: 20,
      maxRequestsPerMinute: 30,
      maxResponseBytes: 1_000_000,
      timeoutMs: 10_000,
    },
    permittedRiskClasses: ["passive"],
    plans: [],
  };

  it("is stable regardless of key order", () => {
    const reordered = JSON.parse(JSON.stringify(base));
    const a = digestScopeManifest(base);
    const b = digestScopeManifest(reordered);
    expect(a).toBe(b);
    expect(a).toMatch(/^[a-f0-9]{64}$/);
  });

  it("ignores a pre-existing digest field", () => {
    const withDigest = { ...base, digest: "deadbeef" };
    expect(digestScopeManifest(withDigest)).toBe(digestScopeManifest(base));
  });

  it("changes when the content changes", () => {
    const changed = { ...base, selectedFindingIds: ["a", "b", "c"] };
    expect(digestScopeManifest(changed)).not.toBe(digestScopeManifest(base));
  });
});

describe("schema round-trips", () => {
  it("applies safe defaults on the target profile", () => {
    const p = liveTargetProfileSchema.parse({
      targetId: "staging",
      baseUrl: "https://staging.example.com",
    });
    expect(p.allowedMethods).toEqual(["GET", "HEAD", "OPTIONS"]);
    expect(p.maxRedirects).toBe(0);
  });

  it("validates a scope manifest", () => {
    const scope = liveScopeManifestSchema.parse({
      projectId: "p",
      targetId: "t",
      baseUrl: "https://staging.example.com",
      allowedOrigins: [],
      allowedMethods: ["GET"],
      allowedPathPrefixes: ["/"],
      identities: [],
      limits: {},
      permittedRiskClasses: ["passive"],
      plans: [],
    });
    expect(scope.limits.maxRequestsPerUnit).toBe(20);
  });
});

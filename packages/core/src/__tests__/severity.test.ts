import { describe, expect, it } from "vitest";
import { findingSchema, revalidationSchema } from "../schemas.js";
import { SEVERITY_ORDER } from "../severity.js";

describe("severity levels", () => {
  const baseFinding = {
    vulnSlug: "other-data-loss",
    title: "Data loss on concurrent writes",
    description: "Race condition causes data loss",
    lineNumbers: [42],
    recommendation: "Add locking",
    confidence: "high" as const,
  };

  it("accepts CRITICAL severity", () => {
    expect(() => findingSchema.parse({ ...baseFinding, severity: "CRITICAL" })).not.toThrow();
  });

  it("accepts HIGH severity", () => {
    expect(() => findingSchema.parse({ ...baseFinding, severity: "HIGH" })).not.toThrow();
  });

  it("accepts MEDIUM severity", () => {
    expect(() => findingSchema.parse({ ...baseFinding, severity: "MEDIUM" })).not.toThrow();
  });

  it("accepts HIGH_BUG severity", () => {
    expect(() => findingSchema.parse({ ...baseFinding, severity: "HIGH_BUG" })).not.toThrow();
  });

  it("accepts BUG severity", () => {
    expect(() => findingSchema.parse({ ...baseFinding, severity: "BUG" })).not.toThrow();
  });

  it("accepts LOW severity", () => {
    expect(() => findingSchema.parse({ ...baseFinding, severity: "LOW" })).not.toThrow();
  });

  it("rejects empty severity", () => {
    expect(() => findingSchema.parse({ ...baseFinding, severity: "" })).toThrow();
  });

  it("uses one canonical ordering including LOW", () => {
    expect(SEVERITY_ORDER).toEqual({
      CRITICAL: 0,
      HIGH: 1,
      MEDIUM: 2,
      HIGH_BUG: 3,
      BUG: 4,
      LOW: 5,
    });
  });
});

describe("revalidation adjustedSeverity", () => {
  const baseRevalidation = {
    verdict: "true-positive" as const,
    reasoning: "Confirmed exploitable",
    revalidatedAt: "2026-04-01T00:00:00Z",
    runId: "run1",
    model: "claude-opus-4-6",
  };

  it("accepts adjustedSeverity HIGH_BUG", () => {
    expect(() =>
      revalidationSchema.parse({ ...baseRevalidation, adjustedSeverity: "HIGH_BUG" }),
    ).not.toThrow();
  });

  it("accepts adjustedSeverity BUG", () => {
    expect(() =>
      revalidationSchema.parse({ ...baseRevalidation, adjustedSeverity: "BUG" }),
    ).not.toThrow();
  });

  it("accepts no adjustedSeverity", () => {
    expect(() => revalidationSchema.parse(baseRevalidation)).not.toThrow();
  });

  it("accepts adjustedSeverity LOW", () => {
    expect(() =>
      revalidationSchema.parse({ ...baseRevalidation, adjustedSeverity: "LOW" }),
    ).not.toThrow();
  });
});

describe("finding with triage and revalidation", () => {
  it("accepts a BUG finding with full triage and revalidation", () => {
    const finding = {
      severity: "BUG",
      vulnSlug: "other-race-condition",
      title: "Race condition in cache invalidation",
      description: "Concurrent requests can see stale data",
      lineNumbers: [100, 105],
      recommendation: "Use atomic operations",
      confidence: "medium",
      triage: {
        priority: "P1",
        exploitability: "moderate",
        impact: "high",
        reasoning: "Could cause data inconsistency in production",
        triagedAt: "2026-04-01T12:00:00Z",
        model: "claude-sonnet-4-6",
      },
      revalidation: {
        verdict: "true-positive",
        reasoning: "Confirmed: no locking around cache update",
        revalidatedAt: "2026-04-01T13:00:00Z",
        runId: "run2",
        model: "claude-opus-4-6",
      },
    };
    expect(() => findingSchema.parse(finding)).not.toThrow();
  });

  it("accepts a HIGH_BUG finding with adjusted severity from revalidation", () => {
    const finding = {
      severity: "HIGH_BUG",
      vulnSlug: "other-data-corruption",
      title: "Silent data corruption on large payloads",
      description: "Buffer overflow truncates data without error",
      lineNumbers: [200],
      recommendation: "Add size validation",
      confidence: "high",
      revalidation: {
        verdict: "true-positive",
        reasoning: "Confirmed: payloads over 1MB are silently truncated",
        adjustedSeverity: "HIGH_BUG",
        revalidatedAt: "2026-04-01T14:00:00Z",
        runId: "run3",
        model: "claude-opus-4-6",
      },
    };
    expect(() => findingSchema.parse(finding)).not.toThrow();
  });
});

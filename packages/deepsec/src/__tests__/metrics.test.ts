import { describe, expect, it } from "vitest";
import { formatCacheHitRate, formatCost, formatPct, formatTokens } from "../commands/metrics.js";

describe("formatCost", () => {
  it("renders $0 exactly", () => {
    expect(formatCost(0)).toBe("$0");
  });

  it("uses 4 decimals for sub-cent costs", () => {
    expect(formatCost(0.0023)).toBe("$0.0023");
  });

  it("uses 3 decimals for sub-dollar costs", () => {
    expect(formatCost(0.045)).toBe("$0.045");
  });

  it("uses 2 decimals between $1 and $100", () => {
    expect(formatCost(1.5)).toBe("$1.50");
    expect(formatCost(42.789)).toBe("$42.79");
  });

  it("drops decimals at $100+", () => {
    expect(formatCost(123.45)).toBe("$123");
  });
});

describe("formatTokens", () => {
  it("returns 0 for zero", () => {
    expect(formatTokens(0)).toBe("0");
  });

  it("returns the raw number under 1K", () => {
    expect(formatTokens(950)).toBe("950");
  });

  it("uses K/M/B suffixes", () => {
    expect(formatTokens(1500)).toBe("1.5K");
    expect(formatTokens(2_500_000)).toBe("2.5M");
    expect(formatTokens(3_500_000_000)).toBe("3.5B");
  });
});

describe("formatPct", () => {
  it("rounds to whole percents", () => {
    expect(formatPct(1, 3)).toBe("33%");
    expect(formatPct(2, 3)).toBe("67%");
  });

  it("returns em-dash on zero denominator (avoids NaN%)", () => {
    expect(formatPct(0, 0)).toBe("—");
  });
});

describe("formatCacheHitRate", () => {
  it("computes cacheRead / total input without double-counting", () => {
    expect(formatCacheHitRate({ input: 20, cacheRead: 80, cacheCreation: 0 })).toBe("80%");
  });

  it("counts cacheCreation as uncached input in the denominator", () => {
    // 800 cached out of 1000 total input (100 uncached + 100 creation + 800 read) → 80%.
    expect(formatCacheHitRate({ input: 100, cacheRead: 800, cacheCreation: 100 })).toBe("80%");
  });

  it("returns em-dash when there is no input", () => {
    expect(formatCacheHitRate({ input: 0, cacheRead: 0, cacheCreation: 0 })).toBe("—");
  });

  it("is 0% when nothing was read from cache", () => {
    expect(formatCacheHitRate({ input: 500, cacheRead: 0, cacheCreation: 0 })).toBe("0%");
  });
});

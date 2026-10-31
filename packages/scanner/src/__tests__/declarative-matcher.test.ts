import { describe, expect, it } from "vitest";
import { z } from "zod";
import {
  compileDeclarativeMatcher,
  compileDeclarativeMatchers,
  type DeclarativeMatcherSpec,
  declarativeMatcherSpecSchema,
  declarativeMatcherSpecsSchema,
} from "../declarative-matcher.js";

function validSpec(overrides: Partial<DeclarativeMatcherSpec> = {}): DeclarativeMatcherSpec {
  return {
    version: 1,
    slug: "generated-queue-consumer",
    description: "Queue consumers that form an untrusted job boundary",
    noiseTier: "noisy",
    filePatterns: ["**/*.{ts,js}"],
    requires: { tech: ["bullmq"], sentinelFiles: ["package.json"] },
    patterns: [
      { source: String.raw`new\s+Worker\s*\(`, label: "BullMQ worker registration" },
      { source: String.raw`job\.data`, flags: "i", label: "Queue job payload" },
    ],
    excludeFilePatterns: ["**/*.test.{ts,js}"],
    examples: ["new Worker(", "JOB.data"],
    closesSurfaceIds: ["queue-consumers"],
    ...overrides,
  };
}

describe("declarativeMatcherSpecSchema", () => {
  it("accepts the bounded data-only format", () => {
    expect(declarativeMatcherSpecSchema.parse(validSpec())).toEqual(validSpec());
  });

  it.each(["g", "s", "u", "gi", "mi"])("rejects unsupported regex flags %s", (flags) => {
    const result = declarativeMatcherSpecSchema.safeParse(
      validSpec({ patterns: [{ source: "worker", flags: flags as "i", label: "worker" }] }),
    );
    expect(result.success).toBe(false);
  });

  it.each([
    ["oversized", "a".repeat(501)],
    ["nested repetition", "(a+)+"],
    ["ambiguous alternation", "(a|aa)+"],
    ["backreference", String.raw`(a+)\1`],
    ["empty match", "a*"],
  ])("rejects unsafe %s regexes", (_name, source) => {
    const result = declarativeMatcherSpecSchema.safeParse(
      validSpec({ patterns: [{ source, label: "unsafe" }], examples: ["aaaa"] }),
    );
    expect(result.success).toBe(false);
  });

  it.each([
    "../src/**",
    "/etc/**",
    "C:/repo/**",
    "!src/**",
    "**/*",
    "**/*.*",
    "{**,**/*}",
    "**/{a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r}.ts",
    "src\\**",
  ])("rejects unsafe or unconstrained glob %s", (filePattern) => {
    expect(
      declarativeMatcherSpecSchema.safeParse(validSpec({ filePatterns: [filePattern] })).success,
    ).toBe(false);
  });

  it("requires every example to exercise a declared regex", () => {
    const result = declarativeMatcherSpecSchema.safeParse(
      validSpec({ examples: ["new Worker(", "does not match"] }),
    );
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues).toContainEqual(
        expect.objectContaining({ path: ["examples", 1] }),
      );
    }
  });

  it("rejects unknown executable-looking fields", () => {
    expect(
      declarativeMatcherSpecSchema.safeParse({
        ...validSpec(),
        match: "() => process.exit(1)",
      }).success,
    ).toBe(false);
  });

  it("rejects duplicate slugs in the complete response schema", () => {
    const result = declarativeMatcherSpecsSchema.safeParse([validSpec(), validSpec()]);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues).toContainEqual(expect.objectContaining({ path: [1, "slug"] }));
    }
  });
});

describe("compileDeclarativeMatcher", () => {
  it("compiles patterns, flags, metadata, and exclusions to a MatcherPlugin", () => {
    const matcher = compileDeclarativeMatcher(validSpec());

    expect(matcher.match("const x = new Worker(\nJOB.data", "src/worker.ts")).toEqual([
      expect.objectContaining({
        vulnSlug: "generated-queue-consumer",
        matchedPattern: "BullMQ worker registration",
        lineNumbers: [1],
      }),
      expect.objectContaining({
        vulnSlug: "generated-queue-consumer",
        matchedPattern: "Queue job payload",
        lineNumbers: [2],
      }),
    ]);
    expect(matcher.match("new Worker(", "src/worker.test.ts")).toEqual([]);
    expect(matcher.closesSurfaceIds).toEqual(["queue-consumers"]);
    expect(matcher.requires).toEqual({
      tech: ["bullmq"],
      sentinelFiles: ["package.json"],
    });
  });

  it("does not retain mutable input data", () => {
    const input = validSpec();
    const matcher = compileDeclarativeMatcher(input);
    input.patterns[0].label = "changed";
    input.closesSurfaceIds.push("another-surface");

    expect(matcher.match("new Worker(", "src/worker.ts")[0].matchedPattern).toBe(
      "BullMQ worker registration",
    );
    expect(matcher.closesSurfaceIds).toEqual(["queue-consumers"]);
    expect(matcher.declarativeSpec.patterns[0].label).toBe("BullMQ worker registration");
  });

  it("rejects a slug already registered by the caller", () => {
    expect(() =>
      compileDeclarativeMatcher(validSpec(), { existingSlugs: ["generated-queue-consumer"] }),
    ).toThrow("Duplicate matcher slug: generated-queue-consumer");
  });

  it("rejects duplicate slugs in a generated set", () => {
    expect(() => compileDeclarativeMatchers([validSpec(), validSpec()])).toThrow(
      "duplicate matcher slug: generated-queue-consumer",
    );
  });

  it("reports schema failures as Zod errors without evaluating input", () => {
    expect(() => compileDeclarativeMatcher({ ...validSpec(), version: 2 })).toThrow(z.ZodError);
  });
});

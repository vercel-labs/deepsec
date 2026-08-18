import type { FileRecord } from "@deepsec/core";
import { describe, expect, it } from "vitest";
import {
  DEFAULT_COVERAGE_POLICY,
  type ExpandedSurfaceInventoryItem,
  evaluateCoverage,
  expandSurfaceInventory,
  groundSurfaceInventory,
  type SurfaceInventoryItem,
  validateSurfaceInventory,
} from "../setup/coverage.js";

function inventory(overrides: Partial<SurfaceInventoryItem> = {}): SurfaceInventoryItem {
  return {
    id: "api-routes",
    kind: "http",
    description: "Public API routes",
    fileGlobs: ["src/routes/**/*.ts"],
    representativeFiles: ["src/routes/users.ts"],
    exposure: "public",
    ...overrides,
  };
}

function expanded(
  overrides: Partial<ExpandedSurfaceInventoryItem> = {},
): ExpandedSurfaceInventoryItem {
  return {
    ...inventory(),
    files: ["src/routes/users.ts"],
    ...overrides,
  };
}

function candidate(filePath: string, runId = "scan-1") {
  return {
    filePath,
    lastScannedRunId: runId,
    candidates: [{}],
  } as Pick<FileRecord, "filePath" | "candidates" | "lastScannedRunId">;
}

describe("surface inventory validation and expansion", () => {
  it("reports untrusted schema values, duplicate ids, unsafe paths, and invalid regexes", () => {
    const issues = validateSurfaceInventory([
      inventory({
        id: "Not Valid",
        fileGlobs: ["../**/*.ts", "!src/private/**"],
        representativeFiles: ["/tmp/route.ts"],
        anchorPatterns: [{ source: "[", flags: "ii" }],
      }),
      inventory({ id: "api-routes" }),
      inventory({ id: "api-routes" }),
    ]);

    expect(issues.map((entry) => entry.field)).toEqual(
      expect.arrayContaining([
        "id",
        "fileGlobs[0]",
        "fileGlobs[1]",
        "representativeFiles[0]",
        "anchorPatterns[0].flags",
      ]),
    );
    expect(issues).toContainEqual(
      expect.objectContaining({ itemIndex: 2, field: "id", message: "must be unique" }),
    );
  });

  it("expands globs using scanner ignores and validates representative paths", () => {
    const result = expandSurfaceInventory(
      [
        inventory({
          representativeFiles: [
            "src/routes/users.ts",
            "src/routes/missing.ts",
            "src/outside.ts",
            "src/routes/users.test.ts",
          ],
        }),
      ],
      [
        "src/routes/users.ts",
        "src/routes/admin.ts",
        "src/routes/users.test.ts",
        "src/outside.ts",
        "node_modules/pkg/route.ts",
        "target/debug/generated.rs",
      ],
    );

    expect(result.sourceFiles).toEqual([
      "src/outside.ts",
      "src/routes/admin.ts",
      "src/routes/users.ts",
    ]);
    expect(result.items[0]?.files).toEqual(["src/routes/admin.ts", "src/routes/users.ts"]);
    expect(result.issues.map((entry) => entry.message)).toEqual(
      expect.arrayContaining([
        "representative file does not exist: src/routes/missing.ts",
        "representative file is outside fileGlobs: src/outside.ts",
        "representative file is ignored: src/routes/users.test.ts",
      ]),
    );
  });

  it("adds project-specific ignores without mutating the input universe", () => {
    const files = ["src/routes/users.ts", "src/routes/generated.ts"];
    const result = expandSurfaceInventory([inventory()], files, {
      ignoreGlobs: ["src/routes/generated.ts"],
    });

    expect(result.items[0]?.files).toEqual(["src/routes/users.ts"]);
    expect(files).toHaveLength(2);
  });

  it("grounds stale representatives and drops surfaces that contain only ignored files", () => {
    const result = groundSurfaceInventory(
      [
        inventory({
          id: "local-oidc",
          fileGlobs: ["crates/proxy/src/oidc.rs"],
          representativeFiles: ["crates/proxy/src/oidc.rs", "crates/proxy/src/config.rs"],
        }),
        inventory({
          id: "application-routes",
          fileGlobs: ["src/routes/**/*.ts"],
          representativeFiles: ["src/routes/removed.ts"],
        }),
        inventory({
          id: "fixture-clis",
          kind: "cli",
          fileGlobs: ["fixtures/**/*.mjs"],
          representativeFiles: ["fixtures/smoke/index.mjs"],
        }),
      ],
      [
        "crates/proxy/src/oidc.rs",
        "crates/proxy/src/config.rs",
        "src/routes/users.ts",
        "fixtures/smoke/index.mjs",
      ],
    );

    expect(result.issues).toEqual([]);
    expect(result.inventory.map((item) => item.id)).toEqual(["local-oidc", "application-routes"]);
    expect(result.inventory[0]).toMatchObject({
      fileGlobs: ["crates/proxy/src/oidc.rs", "crates/proxy/src/config.rs"],
      representativeFiles: ["crates/proxy/src/oidc.rs", "crates/proxy/src/config.rs"],
    });
    expect(result.inventory[1]?.representativeFiles).toEqual(["src/routes/users.ts"]);
    expect(result.changes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          itemId: "local-oidc",
          action: "added-representative-glob",
        }),
        expect.objectContaining({
          itemId: "application-routes",
          action: "replaced-representatives",
        }),
        expect.objectContaining({ itemId: "fixture-clis", action: "dropped-surface" }),
      ]),
    );
    expect(
      expandSurfaceInventory(result.inventory, [
        "crates/proxy/src/oidc.rs",
        "crates/proxy/src/config.rs",
        "src/routes/users.ts",
      ]).issues,
    ).toEqual([]);
  });
});

describe("evaluateCoverage", () => {
  it("requires every representative on surfaces smaller than five files", () => {
    const surface = expanded({
      files: ["src/routes/users.ts", "src/routes/admin.ts", "src/routes/billing.ts"],
      representativeFiles: ["src/routes/users.ts", "src/routes/admin.ts"],
    });
    const report = evaluateCoverage({
      inventory: [surface],
      sourceFiles: surface.files,
      candidateRecords: [candidate("src/routes/users.ts")],
      scanResult: { runId: "scan-1" },
    });

    expect(report.passed).toBe(false);
    expect(report.surfaces[0]).toMatchObject({
      coveredFileCount: 1,
      coveredRepresentativeFileCount: 1,
      passed: false,
    });
    expect(report.reasons[0]).toContain("covered 1/2");
  });

  it("uses inclusive 80% representative and 50% universe boundaries for large surfaces", () => {
    const files = Array.from({ length: 10 }, (_, index) => `src/routes/r${index}.ts`);
    const representativeFiles = files.slice(0, 5);
    const passing = evaluateCoverage({
      inventory: [expanded({ files, representativeFiles })],
      sourceFiles: files,
      candidateRecords: files.slice(0, 5).map((file) => candidate(file)),
      scanResult: { runId: "scan-1" },
    });
    const failing = evaluateCoverage({
      inventory: [expanded({ files, representativeFiles })],
      sourceFiles: files,
      candidateRecords: files.slice(0, 4).map((file) => candidate(file)),
      scanResult: { runId: "scan-1" },
    });

    expect(passing.surfaces[0]).toMatchObject({
      representativeCoverageRatio: 1,
      fileCoverageRatio: 0.5,
      passed: true,
    });
    expect(failing.surfaces[0]?.reasons).toEqual(
      expect.arrayContaining([expect.stringContaining("surface file coverage 40%")]),
    );
  });

  it("always fails zero-covered sensitive kinds and public exposure", () => {
    const internalQueue = expanded({ kind: "queue", exposure: "internal" });
    const publicOther = expanded({ id: "public-other", kind: "other", exposure: "public" });
    const report = evaluateCoverage({
      inventory: [internalQueue, publicOther],
      sourceFiles: ["src/routes/users.ts"],
      candidateRecords: [],
    });

    expect(report.passed).toBe(false);
    expect(
      report.surfaces.every((surface) =>
        surface.reasons.some((reason) => reason.includes("zero covered")),
      ),
    ).toBe(true);
  });

  it("ignores stale records when a scan run id is supplied", () => {
    const report = evaluateCoverage({
      inventory: [expanded()],
      sourceFiles: ["src/routes/users.ts"],
      candidateRecords: [candidate("src/routes/users.ts", "old-scan")],
      scanResult: { runId: "new-scan" },
    });

    expect(report.candidateFileCount).toBe(0);
    expect(report.passed).toBe(false);
  });

  it("emits dominant-language warnings without independently failing coverage", () => {
    const report = evaluateCoverage({
      inventory: [expanded()],
      sourceFiles: ["src/routes/users.ts"],
      candidateRecords: [candidate("src/routes/users.ts")],
      scanResult: {
        runId: "scan-1",
        languageStats: [
          { language: "typescript", scannedFiles: 80, candidates: 0, matchRate: 0 },
          { language: "python", scannedFiles: 20, candidates: 2, matchRate: 0.1 },
        ],
      },
    });

    expect(report.passed).toBe(true);
    expect(report.languageWarnings).toEqual([
      expect.objectContaining({ language: "typescript", sourceShare: 0.8 }),
    ]);
  });

  it("fails only when a new matcher exceeds the strict breadth boundary", () => {
    const files = Array.from({ length: 10 }, (_, index) => `src/routes/r${index}.ts`);
    const surface = expanded({
      files,
      representativeFiles: files.slice(0, 5),
    });
    const atBoundary = evaluateCoverage({
      inventory: [surface],
      sourceFiles: files,
      candidateRecords: files.slice(0, 5).map((file) => candidate(file)),
      newMatcherHits: { "generated-route": files.slice(0, 2) },
      scanResult: { runId: "scan-1" },
    });
    const aboveBoundary = evaluateCoverage({
      inventory: [surface],
      sourceFiles: files,
      candidateRecords: files.slice(0, 5).map((file) => candidate(file)),
      newMatcherHits: { "generated-route": files.slice(0, 3) },
      scanResult: { runId: "scan-1" },
    });

    expect(DEFAULT_COVERAGE_POLICY.matcherMaximumSourceRatio).toBe(0.2);
    expect(DEFAULT_COVERAGE_POLICY.matcherSourceRatioMinimumFiles).toBe(5);
    expect(atBoundary.passed).toBe(true);
    expect(aboveBoundary.passed).toBe(false);
    expect(aboveBoundary.explosionWarnings[0]).toMatchObject({
      matcherSlug: "generated-route",
      matchedFiles: 3,
      sourceRatio: 0.3,
    });
  });

  it("does not reject a one-file matcher solely by ratio in a tiny repository", () => {
    const report = evaluateCoverage({
      inventory: [expanded()],
      sourceFiles: ["src/routes/users.ts", "src/helper.ts"],
      candidateRecords: [candidate("src/routes/users.ts")],
      newMatcherHits: { "generated-route": ["src/routes/users.ts"] },
      scanResult: { runId: "scan-1" },
    });

    expect(report.passed).toBe(true);
    expect(report.explosionWarnings).toEqual([]);
  });
});

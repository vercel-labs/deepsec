import type { FileRecord } from "@deepsec/core";
import { IGNORE_DIRS } from "@deepsec/scanner";
import { minimatch } from "minimatch";

export const SURFACE_KINDS = [
  "http",
  "rpc",
  "queue",
  "cron",
  "cli",
  "webhook",
  "agent-tool",
  "other",
] as const;

export const SURFACE_EXPOSURES = [
  "public",
  "authenticated",
  "internal",
  "mixed",
  "unknown",
] as const;

export type SurfaceKind = (typeof SURFACE_KINDS)[number];
export type SurfaceExposure = (typeof SURFACE_EXPOSURES)[number];

export interface SurfaceInventoryItem {
  id: string;
  kind: SurfaceKind;
  description: string;
  fileGlobs: string[];
  anchorPatterns?: Array<{ source: string; flags?: string }>;
  representativeFiles: string[];
  expectedAuthPrimitives?: string[];
  exposure: SurfaceExposure;
}

export interface ExpandedSurfaceInventoryItem extends SurfaceInventoryItem {
  /** Sorted, POSIX-relative, non-ignored files matched by fileGlobs. */
  files: string[];
}

export interface InventoryValidationIssue {
  itemIndex: number;
  itemId?: string;
  field: string;
  message: string;
}

export interface ExpandedSurfaceInventory {
  items: ExpandedSurfaceInventoryItem[];
  /** The normalized, non-ignored repository universe used for expansion. */
  sourceFiles: string[];
  issues: InventoryValidationIssue[];
}

export interface GroundedSurfaceInventory {
  inventory: SurfaceInventoryItem[];
  changes: Array<{
    itemId: string;
    action: "added-representative-glob" | "replaced-representatives" | "dropped-surface";
    detail: string;
  }>;
  issues: InventoryValidationIssue[];
}

export interface CoveragePolicy {
  version: 1;
  smallSurfaceFileThreshold: number;
  largeSurfaceRepresentativeRatio: number;
  largeSurfaceUniverseRatio: number;
  zeroCoverageKinds: readonly SurfaceKind[];
  zeroCoverageExposures: readonly SurfaceExposure[];
  dominantLanguageMinimumShare: number;
  dominantLanguageMinimumFiles: number;
  lowLanguageMatchRate: number;
  matcherMaximumSourceRatio: number;
  /** Do not apply the ratio-only explosion gate to repositories smaller than this. */
  matcherSourceRatioMinimumFiles: number;
  matcherMaximumFiles: number;
  uncoveredExamplesLimit: number;
}

export const DEFAULT_COVERAGE_POLICY: Readonly<CoveragePolicy> = Object.freeze({
  version: 1,
  smallSurfaceFileThreshold: 5,
  largeSurfaceRepresentativeRatio: 0.8,
  largeSurfaceUniverseRatio: 0.5,
  zeroCoverageKinds: ["http", "rpc", "queue", "cron", "webhook", "agent-tool"],
  zeroCoverageExposures: ["public"],
  dominantLanguageMinimumShare: 0.2,
  dominantLanguageMinimumFiles: 50,
  lowLanguageMatchRate: 0.01,
  matcherMaximumSourceRatio: 0.2,
  matcherSourceRatioMinimumFiles: 5,
  matcherMaximumFiles: 500,
  uncoveredExamplesLimit: 5,
} satisfies CoveragePolicy);

export interface CoverageLanguageStat {
  language: string;
  scannedFiles: number;
  candidates: number;
  matchRate: number;
}

export interface CoverageSurfaceReport {
  id: string;
  kind: SurfaceKind;
  exposure: SurfaceExposure;
  fileCount: number;
  coveredFileCount: number;
  fileCoverageRatio: number;
  representativeFileCount: number;
  coveredRepresentativeFileCount: number;
  representativeCoverageRatio: number;
  uncoveredExamples: string[];
  passed: boolean;
  reasons: string[];
}

export interface CoverageLanguageWarning {
  language: string;
  scannedFiles: number;
  sourceShare: number;
  matchRate: number;
  reason: string;
}

export interface CoverageExplosionWarning {
  matcherSlug: string;
  matchedFiles: number;
  sourceRatio: number;
  reason: string;
}

export interface CoverageReport {
  policyVersion: 1;
  passed: boolean;
  sourceFileCount: number;
  candidateFileCount: number;
  surfaces: CoverageSurfaceReport[];
  languageWarnings: CoverageLanguageWarning[];
  explosionWarnings: CoverageExplosionWarning[];
  reasons: string[];
}

export interface CoverageScanSummary {
  /** When present, stale FileRecords from another scan are ignored. */
  runId?: string;
  languageStats?: CoverageLanguageStat[];
}

export interface EvaluateCoverageInput {
  inventory: readonly ExpandedSurfaceInventoryItem[];
  sourceFiles: readonly string[];
  candidateRecords: ReadonlyArray<Pick<FileRecord, "filePath" | "candidates" | "lastScannedRunId">>;
  scanResult?: CoverageScanSummary;
  /** Per-new-matcher hits. Baseline/built-in candidate breadth is not an explosion. */
  newMatcherHits?: Readonly<Record<string, readonly string[]>>;
  policy?: CoveragePolicy;
}

const ID_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const VALID_REGEX_FLAGS = /^[dgimsuvy]*$/;

function isRelativePath(value: string): boolean {
  return (
    value.length > 0 &&
    !value.startsWith("/") &&
    !value.startsWith("\\") &&
    !/^[A-Za-z]:[\\/]/.test(value) &&
    !value.split(/[\\/]/).includes("..")
  );
}

function normalizedRelativePath(value: string): string | null {
  const normalized = value.replaceAll("\\", "/").replace(/^\.\//, "");
  return isRelativePath(normalized) ? normalized : null;
}

function issue(
  item: unknown,
  itemIndex: number,
  field: string,
  message: string,
): InventoryValidationIssue {
  const itemId =
    typeof item === "object" && item !== null && typeof (item as { id?: unknown }).id === "string"
      ? (item as { id: string }).id
      : undefined;
  return { itemIndex, itemId, field, message };
}

/** Validate untrusted structured inventory output without touching the filesystem. */
export function validateSurfaceInventory(
  inventory: readonly SurfaceInventoryItem[],
): InventoryValidationIssue[] {
  const issues: InventoryValidationIssue[] = [];
  const ids = new Set<string>();

  if (inventory.length === 0) {
    issues.push({ itemIndex: -1, field: "inventory", message: "inventory must not be empty" });
    return issues;
  }

  for (const [index, item] of inventory.entries()) {
    if (!ID_PATTERN.test(item.id)) {
      issues.push(issue(item, index, "id", "must be a lowercase kebab-case identifier"));
    } else if (ids.has(item.id)) {
      issues.push(issue(item, index, "id", "must be unique"));
    }
    ids.add(item.id);

    if (!SURFACE_KINDS.includes(item.kind)) {
      issues.push(issue(item, index, "kind", "is not a supported surface kind"));
    }
    if (!SURFACE_EXPOSURES.includes(item.exposure)) {
      issues.push(issue(item, index, "exposure", "is not a supported exposure"));
    }
    if (!item.description.trim()) {
      issues.push(issue(item, index, "description", "must not be empty"));
    }
    if (item.fileGlobs.length === 0) {
      issues.push(issue(item, index, "fileGlobs", "must contain at least one glob"));
    }
    for (const [globIndex, glob] of item.fileGlobs.entries()) {
      if (!glob.trim() || !isRelativePath(glob) || glob.startsWith("!")) {
        issues.push(
          issue(
            item,
            index,
            `fileGlobs[${globIndex}]`,
            "must be a non-negated path glob constrained to the target root",
          ),
        );
      }
    }
    if (item.representativeFiles.length === 0 || item.representativeFiles.length > 5) {
      issues.push(issue(item, index, "representativeFiles", "must contain between 1 and 5 paths"));
    }
    const representatives = new Set<string>();
    for (const [fileIndex, file] of item.representativeFiles.entries()) {
      const normalized = normalizedRelativePath(file);
      if (!normalized) {
        issues.push(
          issue(
            item,
            index,
            `representativeFiles[${fileIndex}]`,
            "must be constrained to the target root",
          ),
        );
      } else if (representatives.has(normalized)) {
        issues.push(
          issue(
            item,
            index,
            `representativeFiles[${fileIndex}]`,
            "must not duplicate another path",
          ),
        );
      }
      if (normalized) representatives.add(normalized);
    }
    for (const [patternIndex, pattern] of (item.anchorPatterns ?? []).entries()) {
      if (!pattern.source) {
        issues.push(
          issue(item, index, `anchorPatterns[${patternIndex}].source`, "must not be empty"),
        );
        continue;
      }
      if (
        pattern.flags &&
        (!VALID_REGEX_FLAGS.test(pattern.flags) ||
          new Set(pattern.flags).size !== pattern.flags.length)
      ) {
        issues.push(
          issue(
            item,
            index,
            `anchorPatterns[${patternIndex}].flags`,
            "contains invalid or duplicate regular-expression flags",
          ),
        );
        continue;
      }
      try {
        new RegExp(pattern.source, pattern.flags);
      } catch {
        issues.push(
          issue(
            item,
            index,
            `anchorPatterns[${patternIndex}]`,
            "is not a valid regular expression",
          ),
        );
      }
    }
  }
  return issues;
}

/**
 * Reconcile model-generated paths with the exact non-ignored universe the
 * scanner can process. Path/schema security violations remain errors; stale,
 * ignored, or slightly inconsistent model-selected examples are repaired
 * deterministically so they cannot strand resumable setup.
 */
export function groundSurfaceInventory(
  inventory: readonly SurfaceInventoryItem[],
  repositoryFiles: readonly string[],
  options: { ignoreGlobs?: readonly string[] } = {},
): GroundedSurfaceInventory {
  const issues = validateSurfaceInventory(inventory).filter(
    (entry) =>
      !entry.field.startsWith("fileGlobs") && !entry.field.startsWith("representativeFiles"),
  );
  const ignores = [...IGNORE_DIRS, ...(options.ignoreGlobs ?? [])];
  const sourceFiles = [
    ...new Set(
      repositoryFiles
        .map(normalizedRelativePath)
        .filter((file): file is string => file !== null)
        .filter((file) => !ignores.some((glob) => minimatch(file, glob, { dot: true }))),
    ),
  ].sort();
  const sourceSet = new Set(sourceFiles);
  const changes: GroundedSurfaceInventory["changes"] = [];
  const grounded: SurfaceInventoryItem[] = [];

  for (const item of inventory) {
    const globs = [
      ...new Set(
        item.fileGlobs
          .map((glob) => glob.replaceAll("\\", "/").replace(/^\.\//, ""))
          .filter((glob) => isRelativePath(glob) && !glob.startsWith("!")),
      ),
    ];
    let representatives = [
      ...new Set(
        item.representativeFiles
          .map(normalizedRelativePath)
          .filter((file): file is string => file !== null && sourceSet.has(file)),
      ),
    ].slice(0, 5);

    for (const representative of representatives) {
      if (globs.some((glob) => minimatch(representative, glob, { dot: true }))) continue;
      globs.push(representative);
      changes.push({
        itemId: item.id,
        action: "added-representative-glob",
        detail: representative,
      });
    }

    const files = sourceFiles.filter((file) =>
      globs.some((glob) => minimatch(file, glob, { dot: true })),
    );
    if (files.length === 0) {
      changes.push({
        itemId: item.id,
        action: "dropped-surface",
        detail: "no declared files are in the scanner's non-ignored repository universe",
      });
      continue;
    }
    if (representatives.length === 0) {
      representatives = files.slice(0, Math.min(3, files.length));
      changes.push({
        itemId: item.id,
        action: "replaced-representatives",
        detail: representatives.join(", "),
      });
    }
    grounded.push({ ...item, fileGlobs: globs, representativeFiles: representatives });
  }

  if (grounded.length === 0) {
    issues.push({
      itemIndex: -1,
      field: "inventory",
      message: "no surfaces contain non-ignored repository files",
    });
  }
  return { inventory: grounded, changes, issues };
}

/**
 * Expand validated surface globs against a caller-supplied repository file
 * universe. The function intentionally has no I/O and shares the scanner's
 * ignore defaults; callers append project-specific and dynamic data ignores.
 */
export function expandSurfaceInventory(
  inventory: readonly SurfaceInventoryItem[],
  repositoryFiles: readonly string[],
  options: { ignoreGlobs?: readonly string[] } = {},
): ExpandedSurfaceInventory {
  const issues = validateSurfaceInventory(inventory);
  const allFiles = new Set<string>();
  for (const file of repositoryFiles) {
    const normalized = normalizedRelativePath(file);
    if (normalized) allFiles.add(normalized);
  }
  const ignores = [...IGNORE_DIRS, ...(options.ignoreGlobs ?? [])];
  const isIgnored = (file: string) => ignores.some((glob) => minimatch(file, glob, { dot: true }));
  const sourceFiles = [...allFiles].filter((file) => !isIgnored(file)).sort();
  const sourceSet = new Set(sourceFiles);

  const items = inventory.map((item, itemIndex): ExpandedSurfaceInventoryItem => {
    const globs = item.fileGlobs.filter((glob) => isRelativePath(glob) && !glob.startsWith("!"));
    const files = sourceFiles.filter((file) =>
      globs.some((glob) => minimatch(file, glob, { dot: true })),
    );
    const representatives = item.representativeFiles
      .map(normalizedRelativePath)
      .filter((file): file is string => file !== null);

    for (const representative of representatives) {
      if (!allFiles.has(representative)) {
        issues.push(
          issue(
            item,
            itemIndex,
            "representativeFiles",
            `representative file does not exist: ${representative}`,
          ),
        );
      } else if (!sourceSet.has(representative)) {
        issues.push(
          issue(
            item,
            itemIndex,
            "representativeFiles",
            `representative file is ignored: ${representative}`,
          ),
        );
      } else if (!files.includes(representative)) {
        issues.push(
          issue(
            item,
            itemIndex,
            "representativeFiles",
            `representative file is outside fileGlobs: ${representative}`,
          ),
        );
      }
    }
    if (files.length === 0) {
      issues.push(
        issue(item, itemIndex, "fileGlobs", "did not match any non-ignored repository files"),
      );
    }

    return {
      ...item,
      representativeFiles: representatives,
      files,
    };
  });

  return { items, sourceFiles, issues };
}

function ratio(numerator: number, denominator: number): number {
  return denominator === 0 ? 0 : numerator / denominator;
}

function percent(value: number): string {
  return `${Math.round(value * 100)}%`;
}

function normalizedSet(paths: readonly string[]): Set<string> {
  return new Set(paths.map(normalizedRelativePath).filter((file): file is string => file !== null));
}

/** Evaluate whether a completed scan reaches the versioned coverage gate. */
export function evaluateCoverage(input: EvaluateCoverageInput): CoverageReport {
  const policy = input.policy ?? DEFAULT_COVERAGE_POLICY;
  const sourceFiles = normalizedSet(input.sourceFiles);
  const candidateFiles = new Set<string>();
  for (const record of input.candidateRecords) {
    if (input.scanResult?.runId && record.lastScannedRunId !== input.scanResult.runId) continue;
    if (record.candidates.length === 0) continue;
    const normalized = normalizedRelativePath(record.filePath);
    if (normalized && sourceFiles.has(normalized)) candidateFiles.add(normalized);
  }

  const surfaces = input.inventory.map((surface): CoverageSurfaceReport => {
    const files = [...normalizedSet(surface.files)].filter((file) => sourceFiles.has(file));
    const representatives = [...normalizedSet(surface.representativeFiles)];
    const coveredFiles = files.filter((file) => candidateFiles.has(file));
    const coveredRepresentatives = representatives.filter((file) => candidateFiles.has(file));
    const fileCoverageRatio = ratio(coveredFiles.length, files.length);
    const representativeCoverageRatio = ratio(
      coveredRepresentatives.length,
      representatives.length,
    );
    const reasons: string[] = [];

    if (files.length < policy.smallSurfaceFileThreshold) {
      if (coveredRepresentatives.length < representatives.length) {
        reasons.push(
          `small surface requires every representative file; covered ${coveredRepresentatives.length}/${representatives.length}`,
        );
      }
    } else {
      if (representativeCoverageRatio < policy.largeSurfaceRepresentativeRatio) {
        reasons.push(
          `representative coverage ${percent(representativeCoverageRatio)} is below ${percent(policy.largeSurfaceRepresentativeRatio)}`,
        );
      }
      if (fileCoverageRatio < policy.largeSurfaceUniverseRatio) {
        reasons.push(
          `surface file coverage ${percent(fileCoverageRatio)} is below ${percent(policy.largeSurfaceUniverseRatio)}`,
        );
      }
    }

    const zeroCoverageMustFail =
      policy.zeroCoverageKinds.includes(surface.kind) ||
      policy.zeroCoverageExposures.includes(surface.exposure);
    if (coveredFiles.length === 0 && zeroCoverageMustFail) {
      reasons.push(`${surface.exposure} ${surface.kind} surface has zero covered files`);
    }
    if (files.length === 0) reasons.push("surface has no expanded source files");

    return {
      id: surface.id,
      kind: surface.kind,
      exposure: surface.exposure,
      fileCount: files.length,
      coveredFileCount: coveredFiles.length,
      fileCoverageRatio,
      representativeFileCount: representatives.length,
      coveredRepresentativeFileCount: coveredRepresentatives.length,
      representativeCoverageRatio,
      uncoveredExamples: files
        .filter((file) => !candidateFiles.has(file))
        .slice(0, policy.uncoveredExamplesLimit),
      passed: reasons.length === 0,
      reasons,
    };
  });

  const languageWarnings: CoverageLanguageWarning[] = [];
  const knownLanguageFiles = (input.scanResult?.languageStats ?? []).reduce(
    (sum, stat) => sum + stat.scannedFiles,
    0,
  );
  for (const stat of input.scanResult?.languageStats ?? []) {
    const sourceShare = ratio(stat.scannedFiles, knownLanguageFiles);
    if (
      stat.scannedFiles >= policy.dominantLanguageMinimumFiles &&
      sourceShare >= policy.dominantLanguageMinimumShare &&
      stat.matchRate < policy.lowLanguageMatchRate
    ) {
      languageWarnings.push({
        language: stat.language,
        scannedFiles: stat.scannedFiles,
        sourceShare,
        matchRate: stat.matchRate,
        reason: `${stat.language} is ${percent(sourceShare)} of known source files but has a ${percent(stat.matchRate)} match rate; check for a missing surface`,
      });
    }
  }

  const explosionWarnings: CoverageExplosionWarning[] = [];
  for (const [matcherSlug, rawFiles] of Object.entries(input.newMatcherHits ?? {})) {
    const matchedFiles = [...normalizedSet(rawFiles)].filter((file) =>
      sourceFiles.has(file),
    ).length;
    const sourceRatio = ratio(matchedFiles, sourceFiles.size);
    const ratioGateApplies = sourceFiles.size >= policy.matcherSourceRatioMinimumFiles;
    if (
      matchedFiles > policy.matcherMaximumFiles ||
      (ratioGateApplies && sourceRatio > policy.matcherMaximumSourceRatio)
    ) {
      explosionWarnings.push({
        matcherSlug,
        matchedFiles,
        sourceRatio,
        reason: `${matcherSlug} matches ${matchedFiles} files (${percent(sourceRatio)} of non-ignored sources), exceeding the ${policy.matcherMaximumFiles}-file or ${percent(policy.matcherMaximumSourceRatio)} limit`,
      });
    }
  }

  const failedSurfaces = surfaces.filter((surface) => !surface.passed);
  const reasons = failedSurfaces.map((surface) => `${surface.id}: ${surface.reasons.join("; ")}`);
  reasons.push(...explosionWarnings.map((warning) => warning.reason));

  return {
    policyVersion: policy.version,
    passed: failedSurfaces.length === 0 && explosionWarnings.length === 0,
    sourceFileCount: sourceFiles.size,
    candidateFileCount: candidateFiles.size,
    surfaces,
    languageWarnings,
    explosionWarnings,
    reasons,
  };
}

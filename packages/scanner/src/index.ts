import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { FileRecord, MatcherGate } from "@deepsec/core";
import {
  completeRun,
  createRunMeta,
  dataDir,
  ensureProject,
  getRegistry,
  readFileRecord,
  writeFileRecord,
  writeRunMeta,
} from "@deepsec/core";
import { glob, globSync } from "glob";
import { type DetectedTech, detectTech, writeTechJson } from "./detect-tech.js";
import type { MatcherRegistry } from "./matcher-registry.js";
import { createDefaultRegistry } from "./matchers/index.js";
import type { MatcherPlugin, ScannerDriver, ScanProgress } from "./types.js";

export type { DetectedTech } from "./detect-tech.js";
export { detectTech, readTechJson, writeTechJson } from "./detect-tech.js";
export { MatcherRegistry } from "./matcher-registry.js";
export { createDefaultRegistry } from "./matchers/index.js";
export { regexMatcher } from "./matchers/utils.js";
export type { MatcherPlugin, NoiseTier, ScannerDriver, ScanProgress } from "./types.js";

/**
 * Evaluate a matcher's `requires` gate against detected tech + a sentinel-
 * file lookup. Returns true when the matcher should run.
 *
 * Semantics:
 *   - No gate → always runs (preserves legacy behavior).
 *   - `tech: ["laravel"]` → at least one tag must be present.
 *   - `sentinelFiles: [...]` → at least one path must exist (or match a
 *     glob); when `sentinelContains` is provided, the file content must
 *     also satisfy the predicate.
 *   - When both are present, EITHER passing is enough — gates are unions,
 *     not intersections. This keeps "tech detector knows you, OR you have
 *     this specific lockfile shape" simple.
 */
export function evaluateGate(
  gate: MatcherGate | undefined,
  detected: DetectedTech,
  rootPath: string,
): boolean {
  if (!gate) return true;

  if (gate.tech && gate.tech.length > 0) {
    const have = new Set(detected.tags);
    if (gate.tech.some((t) => have.has(t))) return true;
  }

  if (gate.sentinelFiles && gate.sentinelFiles.length > 0) {
    for (const pattern of gate.sentinelFiles) {
      // Synchronous glob — gate evaluation is rare (once per scan) and
      // we don't want to bubble async up into the registry.
      const candidates = pattern.includes("*")
        ? (globSync(pattern, {
            cwd: rootPath,
            ignore: ["**/node_modules/**", "**/dist/**", "**/.git/**"],
            nodir: true,
            absolute: false,
          }) as string[])
        : fs.existsSync(path.join(rootPath, pattern))
          ? [pattern]
          : [];

      for (const rel of candidates) {
        if (!gate.sentinelContains) return true;
        try {
          const content = fs.readFileSync(path.join(rootPath, rel), "utf-8");
          if (gate.sentinelContains(rel, content)) return true;
        } catch {
          // unreadable; treat as miss
        }
      }
    }
  }

  return false;
}

/** Build a registry that merges the built-in matchers with any contributed by plugins. */
function buildMergedRegistry(): MatcherRegistry {
  const registry = createDefaultRegistry();
  for (const m of getRegistry().matchers) {
    registry.register(m);
  }
  return registry;
}

/** Returns the noise tier for a given vulnSlug. Defaults to "normal". */
export function getNoiseTier(slug: string): import("./types.js").NoiseTier {
  const registry = buildMergedRegistry();
  return registry.getBySlug(slug)?.noiseTier ?? "normal";
}

/** Score a file by its best (most precise) matcher. Lower = higher priority. */
export function noiseScore(slugs: string[]): number {
  const tierValues = { precise: 0, normal: 1, noisy: 2 };
  if (slugs.length === 0) return 3;
  return Math.min(...slugs.map((s) => tierValues[getNoiseTier(s)] ?? 1));
}

const _SCANNER_VERSION = "0.1.0";

const IGNORE_DIRS = [
  "**/node_modules/**",
  "**/.git/**",
  "**/dist/**",
  "**/build/**",
  "**/.next/**",
  "**/coverage/**",
  "**/.turbo/**",
  "**/__tests__/**",
  "**/*.test.{ts,tsx,js,jsx}",
  "**/*.spec.{ts,tsx,js,jsx}",
  "**/test/**",
  "**/tests/**",
  "**/fixtures/**",
  "**/testserver/**",
  "**/*.d.ts",
  "**/jest-setup.*",
  "**/*.mdx",
  "**/*.md",
  "**/content/docs/**",
  "**/content/docs-wip/**",
];

export class RegexScannerDriver implements ScannerDriver {
  async *scan(params: {
    root: string;
    matchers: MatcherPlugin[];
    projectId: string;
    runId: string;
    /** Extra ignore globs merged with the built-in defaults */
    ignorePaths?: string[];
  }): AsyncGenerator<ScanProgress, FileRecord[]> {
    const { root, matchers, projectId, runId } = params;
    const ignore = [...IGNORE_DIRS, ...(params.ignorePaths ?? [])];
    const upserted = new Map<string, FileRecord>();

    // Pre-glob: deduplicate file patterns across matchers
    const patternKey = (patterns: string[]) => patterns.sort().join("|");
    const globCache = new Map<string, string[]>();

    // Group matchers by their file patterns to avoid redundant globs
    const matchersByPattern = new Map<string, MatcherPlugin[]>();
    for (const matcher of matchers) {
      const key = patternKey(matcher.filePatterns);
      const list = matchersByPattern.get(key) ?? [];
      list.push(matcher);
      matchersByPattern.set(key, list);
    }

    // Pre-glob all unique patterns
    const uniquePatterns = [...matchersByPattern.entries()];
    let globsDone = 0;
    for (const [key, group] of uniquePatterns) {
      if (globCache.has(key)) continue;
      globsDone++;
      yield {
        type: "matcher_started" as const,
        message: `Globbing pattern ${globsDone}/${uniquePatterns.length}: ${group[0].filePatterns.slice(0, 3).join(", ")}${group[0].filePatterns.length > 3 ? "..." : ""}`,
        matcherSlug: "glob",
      };
      const rawFiles = await glob(group[0].filePatterns, {
        cwd: root,
        ignore,
        nodir: true,
        absolute: false,
      });
      // glob returns native separators on Windows ("src\api\foo.ts").
      // Record paths require POSIX separators (assertSafeFilePath rejects
      // "\"), so normalize once here before anything reads or writes records.
      const files = rawFiles.map((f) => f.replaceAll("\\", "/"));
      globCache.set(key, files);
      yield {
        type: "matcher_done" as const,
        message: `Found ${files.length} files`,
        matcherSlug: "glob",
        matchCount: files.length,
      };
    }

    const contentCache = new Map<string, string>();

    const matcherTotal = matchers.length;
    for (let mi = 0; mi < matchers.length; mi++) {
      const matcher = matchers[mi];
      yield {
        type: "matcher_started",
        message: `Running matcher: ${matcher.slug}`,
        matcherSlug: matcher.slug,
        matcherIndex: mi + 1,
        matcherTotal,
      };

      let matchCount = 0;

      const key = patternKey(matcher.filePatterns);
      const files = globCache.get(key) ?? [];

      for (const relPath of files) {
        let content = contentCache.get(relPath);
        if (content === undefined) {
          try {
            // Normalize CRLF → LF so matchers that split on "\n" don't see
            // a trailing "\r" on every line. Without this, regexes anchored
            // with `$` silently fail to match on Windows-checked-out files
            // (and any mixed-EOL repo). Note: byte offsets reported by
            // matchers are now into the normalized content, not the raw
            // file on disk — line numbers stay correct, but if a matcher
            // ever needs raw byte offsets it has to redo the read itself.
            content = fs.readFileSync(path.join(root, relPath), "utf-8").replaceAll("\r\n", "\n");
            contentCache.set(relPath, content);
          } catch {
            contentCache.set(relPath, "");
            continue;
          }
        }
        if (!content) continue;

        const matches = matcher.match(content, relPath);
        if (matches.length === 0) continue;

        matchCount += matches.length;

        // Upsert: load existing or create new
        let record = upserted.get(relPath);
        if (!record) {
          record = readFileRecord(projectId, relPath) ?? {
            filePath: relPath,
            projectId,
            candidates: [],
            lastScannedAt: "",
            lastScannedRunId: "",
            fileHash: "",
            findings: [],
            analysisHistory: [],
            status: "pending",
          };
          upserted.set(relPath, record);
        }

        // Merge matches — don't duplicate
        for (const m of matches) {
          const exists = record.candidates.some(
            (c) =>
              c.vulnSlug === m.vulnSlug &&
              c.matchedPattern === m.matchedPattern &&
              c.lineNumbers.join(",") === m.lineNumbers.join(","),
          );
          if (!exists) {
            record.candidates.push(m);
          }
        }

        const _stat = fs.statSync(path.join(root, relPath));
        const hash = crypto.createHash("sha256").update(content).digest("hex");

        record.lastScannedAt = new Date().toISOString();
        record.lastScannedRunId = runId;
        record.fileHash = hash;

        // Only reset to pending if not already analyzed
        // (re-scanning doesn't invalidate previous analysis)

        yield {
          type: "file_scanned",
          message: `Found ${matches.length} match(es) in ${relPath}`,
          filePath: relPath,
          matchCount: matches.length,
        };
      }

      yield {
        type: "matcher_done",
        message: `Matcher ${matcher.slug}: ${matchCount} match(es)`,
        matcherSlug: matcher.slug,
        matchCount,
        matcherIndex: mi + 1,
        matcherTotal,
      };
    }

    // Write all upserted records to disk
    for (const record of upserted.values()) {
      writeFileRecord(record);
    }

    return Array.from(upserted.values());
  }
}

/**
 * Per-language scan stats. Emitted on the scan result so downstream tools
 * (CLI warning, analytics) can spot ecosystems where deepsec has weak
 * coverage. `matchRate` is `candidates / scannedFiles` for that language;
 * very low rates on a language with significant file count signal we
 * should ship more matchers (or the user should write a custom plugin).
 */
export interface LanguageStats {
  language: string;
  scannedFiles: number;
  candidates: number;
  matchRate: number;
}

const LANGUAGE_EXTENSIONS: Record<string, string[]> = {
  typescript: [".ts", ".tsx", ".cts", ".mts"],
  javascript: [".js", ".jsx", ".cjs", ".mjs"],
  python: [".py"],
  ruby: [".rb"],
  php: [".php"],
  go: [".go"],
  rust: [".rs"],
  java: [".java"],
  kotlin: [".kt", ".kts"],
  csharp: [".cs"],
  lua: [".lua"],
  terraform: [".tf"],
};

function languageOf(filePath: string): string | null {
  const ext = path.extname(filePath).toLowerCase();
  for (const [lang, exts] of Object.entries(LANGUAGE_EXTENSIONS)) {
    if (exts.includes(ext)) return lang;
  }
  return null;
}

/**
 * Run a full scan: ensure project, create run, scan files, upsert FileRecords.
 */
export async function scan(params: {
  projectId: string;
  root: string;
  matcherSlugs?: string[];
  /**
   * Extra ignore globs (added to the built-in defaults). When omitted,
   * `data/<projectId>/config.json:ignorePaths` is consulted.
   */
  ignorePaths?: string[];
  driver?: ScannerDriver;
  onProgress?: (progress: ScanProgress) => void;
}): Promise<{
  runId: string;
  candidateCount: number;
  detected: DetectedTech;
  /** Matchers that were active for this run (after gate evaluation). */
  activeMatchers: string[];
  /** Matchers skipped because their `requires` gate failed. */
  skippedMatchers: string[];
  /**
   * Per-language match rate. Languages with ≥50 files and matchRate < 1%
   * are good candidates for the low-coverage warning the CLI surfaces.
   */
  languageStats: LanguageStats[];
}> {
  const registry = buildMergedRegistry();
  const allSelected = params.matcherSlugs
    ? registry.getBySlugs(params.matcherSlugs)
    : registry.getAll();

  if (allSelected.length === 0) {
    throw new Error("No matchers selected");
  }

  ensureProject(params.projectId, params.root);

  // Tech detection runs once per scan. Matcher gates and the prompt
  // assembler share this single detection pass.
  const detected = detectTech(params.root);
  writeTechJson(params.projectId, detected);

  // Gate evaluation: drop matchers whose `requires` clause doesn't match
  // this repo. Matchers without `requires` always run.
  //
  // Explicit `--matchers <slug>` is a stronger signal than the gate —
  // when the caller named the matchers, honor every single one. We do
  // this per-matcher (not "only if all are gated out") because mixing
  // gated and ungated slugs in `--matchers ...,xss` would otherwise
  // silently drop the gated half: `xss` runs, the gated slug is
  // dropped, and the user has no way to know.
  const honorAllSelected = !!params.matcherSlugs;
  const activeMatchers: MatcherPlugin[] = [];
  const skipped: string[] = [];
  const absRoot = path.resolve(params.root);
  for (const m of allSelected) {
    if (honorAllSelected || evaluateGate(m.requires, detected, absRoot)) {
      activeMatchers.push(m);
    } else {
      skipped.push(m.slug);
    }
  }
  const matchers = activeMatchers;

  const meta = createRunMeta({
    projectId: params.projectId,
    rootPath: params.root,
    type: "scan",
    scannerConfig: {
      matcherSlugs: matchers.map((m) => m.slug),
    },
  });
  writeRunMeta(meta);

  // Merge explicit ignorePaths with project config.json:ignorePaths
  let ignorePaths = params.ignorePaths;
  if (!ignorePaths) {
    try {
      const cfgPath = path.resolve(dataDir(params.projectId), "config.json");
      if (fs.existsSync(cfgPath)) {
        const cfg = JSON.parse(fs.readFileSync(cfgPath, "utf-8"));
        if (Array.isArray(cfg.ignorePaths)) ignorePaths = cfg.ignorePaths;
      }
    } catch {
      // ignore — fall through with no extra ignores
    }
  }

  const driver = params.driver ?? new RegexScannerDriver();
  const gen = driver.scan({
    root: path.resolve(params.root),
    matchers,
    projectId: params.projectId,
    runId: meta.runId,
    ignorePaths,
  });

  let result = await gen.next();
  while (!result.done) {
    try {
      if (params.onProgress) {
        params.onProgress(result.value as ScanProgress);
      }
    } catch {
      // Never let progress callback crash scan
    }
    result = await gen.next();
  }

  const records = result.value as FileRecord[];

  // Language stats: walk the source tree once for each known extension to
  // get the denominator (total source files), then count records to get
  // the numerator (files with candidates). This is intentionally a second
  // pass — keeps the driver itself unaware of language taxonomy.
  const ignore = [
    "**/node_modules/**",
    "**/.git/**",
    "**/dist/**",
    "**/build/**",
    "**/.next/**",
    "**/coverage/**",
    "**/.turbo/**",
    "**/vendor/**",
    "**/__tests__/**",
    "**/test/**",
    "**/tests/**",
    "**/*.test.*",
    "**/*.spec.*",
    "**/fixtures/**",
    ...(ignorePaths ?? []),
  ];
  const languageStats: LanguageStats[] = [];
  const recordsByLang = new Map<string, number>();
  for (const r of records) {
    const lang = languageOf(r.filePath);
    if (!lang) continue;
    recordsByLang.set(lang, (recordsByLang.get(lang) ?? 0) + 1);
  }
  for (const [lang, exts] of Object.entries(LANGUAGE_EXTENSIONS)) {
    try {
      const patterns = exts.map((e) => `**/*${e}`);
      const files = await glob(patterns, {
        cwd: path.resolve(params.root),
        ignore,
        nodir: true,
        absolute: false,
      });
      const scanned = files.length;
      const candidates = recordsByLang.get(lang) ?? 0;
      if (scanned === 0) continue;
      languageStats.push({
        language: lang,
        scannedFiles: scanned,
        candidates,
        matchRate: scanned === 0 ? 0 : candidates / scanned,
      });
    } catch {
      // Single-language failure shouldn't kill the scan summary.
    }
  }

  completeRun(params.projectId, meta.runId, "done", {
    filesScanned: records.length,
    candidatesFound: records.reduce((s, r) => s + r.candidates.length, 0),
  });

  return {
    runId: meta.runId,
    candidateCount: records.length,
    detected,
    activeMatchers: matchers.map((m) => m.slug),
    skippedMatchers: skipped,
    languageStats,
  };
}

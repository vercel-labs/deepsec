import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { FileRecord } from "@deepsec/core";
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
import { glob } from "glob";
import type { MatcherRegistry } from "./matcher-registry.js";
import { createDefaultRegistry } from "./matchers/index.js";
import type { MatcherPlugin, ScannerDriver, ScanProgress } from "./types.js";

export { MatcherRegistry } from "./matcher-registry.js";
export { createDefaultRegistry } from "./matchers/index.js";
export { regexMatcher } from "./matchers/utils.js";
export type { MatcherPlugin, NoiseTier, ScannerDriver, ScanProgress } from "./types.js";

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
      const files = await glob(group[0].filePatterns, {
        cwd: root,
        ignore,
        nodir: true,
        absolute: false,
      });
      globCache.set(key, files);
      yield {
        type: "matcher_done" as const,
        message: `Found ${files.length} files`,
        matcherSlug: "glob",
        matchCount: files.length,
      };
    }

    const contentCache = new Map<string, string>();

    for (const matcher of matchers) {
      yield {
        type: "matcher_started",
        message: `Running matcher: ${matcher.slug}`,
        matcherSlug: matcher.slug,
      };

      let matchCount = 0;

      const key = patternKey(matcher.filePatterns);
      const files = globCache.get(key) ?? [];

      for (const relPath of files) {
        let content = contentCache.get(relPath);
        if (content === undefined) {
          try {
            content = fs.readFileSync(path.join(root, relPath), "utf-8");
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
}): Promise<{ runId: string; candidateCount: number }> {
  const registry = buildMergedRegistry();
  const matchers = params.matcherSlugs
    ? registry.getBySlugs(params.matcherSlugs)
    : registry.getAll();

  if (matchers.length === 0) {
    throw new Error("No matchers selected");
  }

  ensureProject(params.projectId, params.root);

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

  completeRun(params.projectId, meta.runId, "done", {
    filesScanned: records.length,
    candidatesFound: records.reduce((s, r) => s + r.candidates.length, 0),
  });

  return { runId: meta.runId, candidateCount: records.length };
}

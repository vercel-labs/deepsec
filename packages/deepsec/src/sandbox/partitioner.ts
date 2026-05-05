import fs from "node:fs";
import path from "node:path";
import type { FileRecord, Severity } from "@deepsec/core";
import { dataDir, loadAllFileRecords, SEVERITY_ORDER } from "@deepsec/core";
import { noiseScore } from "@deepsec/scanner";
import type { PartitionResult, SandboxSubcommand } from "./types.js";

/**
 * Load eligible files for the given command and split into N disjoint partitions.
 */
export function partitionFiles(
  projectId: string,
  numPartitions: number,
  opts: {
    command?: SandboxSubcommand;
    limit?: number;
    filter?: string;
    reinvestigate?: boolean | number;
    force?: boolean;
    minSeverity?: string;
    /** Agent type currently being run; used to scope --reinvestigate counting */
    agentType?: string;
  } = {},
): PartitionResult {
  const allRecords = loadAllFileRecords(projectId);
  const command = opts.command ?? "process";
  const agentType = opts.agentType ?? "claude-agent-sdk";

  let eligible: FileRecord[];

  switch (command) {
    case "process":
      if (typeof opts.reinvestigate === "number") {
        const marker = opts.reinvestigate;
        // `--reinvestigate <N>` is a wave marker. Skip files that already
        // have a productive analysis by the same agent bearing this marker.
        // Mirrors processor/index.ts.
        eligible = allRecords.filter((r) => {
          const alreadyDone = (r.analysisHistory ?? []).some((h) => {
            if ((h.usage?.outputTokens ?? 0) <= 0) return false;
            if (h.agentType !== agentType) return false;
            return h.reinvestigateMarker === marker;
          });
          return !alreadyDone;
        });
      } else if (opts.reinvestigate) {
        eligible = allRecords;
      } else {
        eligible = allRecords.filter(
          (r) => r.status === "pending" || r.status === "error" || r.status === "processing",
        );
      }
      break;

    case "revalidate": {
      const minSev = opts.minSeverity ? SEVERITY_ORDER[opts.minSeverity as Severity] : undefined;
      eligible = allRecords.filter((r) => {
        if (r.findings.length === 0) return false;
        const unrevalidated = r.findings.filter((f) => {
          if (!opts.force && f.revalidation) return false;
          if (minSev !== undefined && SEVERITY_ORDER[f.severity] > minSev) return false;
          return true;
        });
        return unrevalidated.length > 0;
      });
      break;
    }

    default:
      eligible = allRecords;
  }

  if (opts.filter) {
    eligible = eligible.filter((r) => r.filePath.startsWith(opts.filter!));
  }

  // Sort by priority
  const projectConfigJsonPath = path.join(dataDir(projectId), "config.json");
  let priorityPaths: string[] = [];
  try {
    const config = JSON.parse(fs.readFileSync(projectConfigJsonPath, "utf-8"));
    priorityPaths = config.priorityPaths ?? [];
  } catch {}

  eligible.sort((a, b) => {
    if (command === "revalidate") {
      // Sort by severity (CRITICAL first)
      const aBest = Math.min(...a.findings.map((f) => SEVERITY_ORDER[f.severity] ?? 99));
      const bBest = Math.min(...b.findings.map((f) => SEVERITY_ORDER[f.severity] ?? 99));
      if (aBest !== bBest) return aBest - bBest;
    }

    const aSlugs = a.candidates.map((c) => c.vulnSlug);
    const bSlugs = b.candidates.map((c) => c.vulnSlug);
    const noiseDiff = noiseScore(aSlugs) - noiseScore(bSlugs);
    if (noiseDiff !== 0) return noiseDiff;

    if (priorityPaths.length > 0) {
      const aPri = priorityPaths.findIndex((p) => a.filePath.startsWith(p));
      const bPri = priorityPaths.findIndex((p) => b.filePath.startsWith(p));
      const aScore = aPri === -1 ? priorityPaths.length : aPri;
      const bScore = bPri === -1 ? priorityPaths.length : bPri;
      if (aScore !== bScore) return aScore - bScore;
    }

    return b.candidates.length - a.candidates.length;
  });

  if (opts.limit && eligible.length > opts.limit) {
    eligible = eligible.slice(0, opts.limit);
  }

  const totalFiles = eligible.length;

  if (numPartitions <= 1 || totalFiles === 0) {
    return {
      partitions: [eligible.map((r) => r.filePath)],
      totalFiles,
    };
  }

  // Group by directory — use enough depth to get at least numPartitions groups
  const dirGroups = new Map<string, string[]>();
  let depth = 1;
  while (depth <= 4) {
    dirGroups.clear();
    for (const record of eligible) {
      const parts = record.filePath.split("/");
      const dir = parts.slice(0, depth).join("/") || record.filePath;
      if (!dirGroups.has(dir)) dirGroups.set(dir, []);
      dirGroups.get(dir)!.push(record.filePath);
    }
    // Enough groups to fill the partitions, or we've gone deep enough
    if (dirGroups.size >= numPartitions || depth >= 4) break;
    depth++;
  }

  // Split oversized groups so no single group dominates a partition
  const targetSize = Math.ceil(totalFiles / numPartitions);
  const chunks: string[][] = [];
  for (const [, files] of dirGroups) {
    if (files.length <= targetSize) {
      chunks.push(files);
    } else {
      for (let i = 0; i < files.length; i += targetSize) {
        chunks.push(files.slice(i, i + targetSize));
      }
    }
  }

  // Sort largest first for better bin packing
  chunks.sort((a, b) => b.length - a.length);

  // Bin packing: assign each chunk to the partition with fewest files
  const partitions: string[][] = Array.from({ length: numPartitions }, () => []);
  for (const chunk of chunks) {
    let minIdx = 0;
    for (let i = 1; i < partitions.length; i++) {
      if (partitions[i].length < partitions[minIdx].length) minIdx = i;
    }
    partitions[minIdx].push(...chunk);
  }

  const nonEmpty = partitions.filter((p) => p.length > 0);
  return { partitions: nonEmpty, totalFiles };
}

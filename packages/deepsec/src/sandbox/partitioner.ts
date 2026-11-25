import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { FileRecord, RunMeta } from "@deepsec/core";
import { dataDir, isPidAlive, loadAllFileRecords, readRunMeta } from "@deepsec/core";
import { noiseScore } from "@deepsec/scanner";
import type { PartitionResult, SandboxSubcommand } from "./types.js";

const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  HIGH_BUG: 3,
  BUG: 4,
};

/**
 * Locks from sandbox workers name a run on another host, so neither PID
 * liveness nor the processor's 1h stale-lock cutoff applies: a sandbox run
 * can legitimately hold files for up to its 5h timeout.
 */
const SANDBOX_STALE_LOCK_MS = 6 * 60 * 60 * 1000;
const MAX_LOCK_CLOCK_SKEW_MS = 5 * 60 * 1000;

/**
 * True when a `processing` record is still held by a run that may finish
 * it. Partitioning such a file again would run it twice while another
 * wave is in flight.
 */
export function hasLiveLock(
  projectId: string,
  r: FileRecord,
  metaCache: Map<string, RunMeta | null> = new Map(),
  now = Date.now(),
): boolean {
  if (r.status !== "processing" || !r.lockedByRunId) return false;
  if (!metaCache.has(r.lockedByRunId)) {
    try {
      metaCache.set(r.lockedByRunId, readRunMeta(projectId, r.lockedByRunId));
    } catch {
      metaCache.set(r.lockedByRunId, null);
    }
  }
  const meta = metaCache.get(r.lockedByRunId);
  if (!meta || meta.phase === "done" || meta.phase === "error") return false;
  if (meta.hostname === os.hostname() && meta.pid !== undefined && !isPidAlive(meta.pid))
    return false;
  const lockedAt = r.lockedAt ? Date.parse(r.lockedAt) : Number.NaN;
  if (!Number.isFinite(lockedAt)) return false;
  // Lock timestamps come from worker-written records. One far in the future
  // (clock skew or tampering) would otherwise hold the file indefinitely.
  if (lockedAt > now + MAX_LOCK_CLOCK_SKEW_MS) return false;
  return now - lockedAt < SANDBOX_STALE_LOCK_MS;
}

/**
 * Files assigned to other active sandbox runs of the same command, from
 * their saved run states: partitions reserved but not dispatched yet, and
 * dispatched sandboxes that haven't been collected. Revalidation takes no
 * file locks, and a `process` worker's locks only reach this host at its
 * first sync, so the run states are the record of what another run still
 * has queued. Each entry expires a sandbox lifetime after its own dispatch
 * (or the launch, while reserved), so a crashed run's leftover state can't
 * hold files forever.
 */
function filesHeldByActiveRuns(projectId: string, command: string, now = Date.now()): Set<string> {
  const held = new Set<string>();
  const dir = path.join(dataDir(projectId), "sandbox-runs");
  let names: string[] = [];
  try {
    names = fs.readdirSync(dir).filter((f) => f.endsWith(".json"));
  } catch {
    return held;
  }
  for (const name of names) {
    try {
      const state = JSON.parse(fs.readFileSync(path.join(dir, name), "utf-8")) as {
        command?: string;
        launchedAt?: string;
        sandboxes?: Array<{ manifest?: string[]; dispatchedAt?: string }>;
        reserved?: Array<{ manifest?: string[] }>;
      };
      if (state.command !== command) continue;
      const active = (since: string | undefined) => {
        const t = Date.parse(since ?? "");
        return Number.isFinite(t) && now - t <= SANDBOX_STALE_LOCK_MS;
      };
      for (const sb of state.sandboxes ?? []) {
        if (!active(sb.dispatchedAt ?? state.launchedAt)) continue;
        for (const f of sb.manifest ?? []) held.add(f);
      }
      if (active(state.launchedAt)) {
        for (const r of state.reserved ?? []) for (const f of r.manifest ?? []) held.add(f);
      }
    } catch {}
  }
  return held;
}

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
  const metaCache = new Map<string, RunMeta | null>();
  const now = Date.now();
  const command = opts.command ?? "process";
  // Files another run is still working on, or has assigned to its workers,
  // are never handed out again. Only partitioned commands claim files; other
  // commands (scan) count every record.
  const claims = command === "process" || command === "revalidate";
  const held = claims ? filesHeldByActiveRuns(projectId, command, now) : new Set<string>();
  const allRecords = loadAllFileRecords(projectId).filter(
    (r) => !claims || (!held.has(r.filePath) && !hasLiveLock(projectId, r, metaCache, now)),
  );
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
            // Mirror processor/index.ts: revalidate entries don't count
            // as "already processed" for a reinvestigate wave.
            if (h.phase === "revalidate") return false;
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
      eligible = allRecords.filter((r) => {
        if (r.findings.length === 0) return false;
        const unrevalidated = r.findings.filter((f) => {
          if (!opts.force && f.revalidation) return false;
          if (opts.minSeverity && SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[opts.minSeverity])
            return false;
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

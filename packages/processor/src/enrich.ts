import { execSync, spawnSync } from "node:child_process";
import path from "node:path";
import type { FileRecord, Severity } from "@deepsec/core";
import {
  defaultConcurrency,
  getRegistry,
  loadAllFileRecords,
  readProjectConfig,
  writeFileRecord,
} from "@deepsec/core";

interface Committer {
  name: string;
  email: string;
  date: string;
}

/**
 * Derive the "org/repo" identifier from the git remote origin URL.
 * Handles both HTTPS and SSH remote formats.
 */
function getRepoFromGitRemote(rootPath: string): string | null {
  try {
    const url = execSync("git remote get-url origin", {
      cwd: rootPath,
      encoding: "utf-8",
      timeout: 5_000,
    }).trim();

    // SSH SCP syntax: git@github.com:owner/repo.git
    const sshMatch = url.match(/git@[^:]+:(.+?)(?:\.git)?$/);
    if (sshMatch) return sshMatch[1];

    // SSH URI syntax: ssh://git@github.com/owner/repo.git
    const sshUriMatch = url.match(/ssh:\/\/[^/]+\/(.+?)(?:\.git)?$/);
    if (sshUriMatch) return sshUriMatch[1];

    // HTTPS: https://github.com/owner/repo.git
    const httpsMatch = url.match(/github\.com\/(.+?)(?:\.git)?$/);
    if (httpsMatch) return httpsMatch[1];

    return null;
  } catch {
    return null;
  }
}

/**
 * Enrich a single FileRecord with git committer info and ownership oracle data.
 * Writes to the record in place (does NOT call writeFileRecord).
 */
export function enrichFileRecord(record: FileRecord, rootPath: string): void {
  const committers = getRecentCommitters(rootPath, record.filePath);
  record.gitInfo = {
    recentCommitters: committers,
    enrichedAt: new Date().toISOString(),
    // Preserve existing ownership data during sync enrichment
    ownership: record.gitInfo?.ownership,
  };
}

function getRecentCommitters(rootPath: string, filePath: string, count: number = 5): Committer[] {
  const absPath = path.join(rootPath, filePath);
  // argv form (no shell). filePath comes from glob output and may contain
  // shell metacharacters; absPath inherits them. Passing as a single argv
  // slot keeps it from being re-parsed as a command.
  const result = spawnSync(
    "git",
    ["log", "--pretty=format:%an\t%ae\t%aI", "-n", String(count), "--", absPath],
    {
      cwd: rootPath,
      encoding: "utf-8",
      timeout: 10_000,
      // Silence stderr — on sandboxes we strip .git so every call fails;
      // empty output below handles cleanly.
      stdio: ["ignore", "pipe", "ignore"],
    },
  );
  if (result.status !== 0) return [];
  const output = result.stdout ?? "";
  if (!output.trim()) return [];

  // Dedupe by email, keep most recent
  const seen = new Map<string, Committer>();
  for (const line of output.trim().split("\n")) {
    const [name, email, date] = line.split("\t");
    if (name && email && date && !seen.has(email)) {
      seen.set(email, { name, email, date });
    }
  }
  return Array.from(seen.values()).slice(0, count);
}

/**
 * Build a per-file committer index in a single `git log --name-only` shell
 * invocation. Returns an empty Map if `rootPath` isn't a git repo (e.g.
 * sandbox runs that strip .git from the target upload).
 */
function buildGitCommitterIndex(
  rootPath: string,
  opts: { since?: string; count?: number } = {},
): Map<string, Committer[]> {
  const index = new Map<string, Committer[]>();
  const count = opts.count ?? 5;
  const since = opts.since ?? "1 year ago";
  // argv form (no shell). The `since` value is hardcoded today, but a
  // future caller passing user input would otherwise inject through the
  // template literal.
  const result = spawnSync(
    "git",
    ["log", `--since=${since}`, "--pretty=format:COMMIT\t%an\t%ae\t%aI", "--name-only", "--", "."],
    {
      cwd: rootPath,
      encoding: "utf-8",
      maxBuffer: 2 * 1024 * 1024 * 1024, // 2 GB — large monorepos push past the default 1 MB
      timeout: 5 * 60 * 1000,
      stdio: ["ignore", "pipe", "ignore"],
    },
  );
  if (result.status !== 0) return index;
  const output = result.stdout ?? "";
  let cur: Committer | null = null;
  for (const line of output.split("\n")) {
    if (line.startsWith("COMMIT\t")) {
      const parts = line.split("\t");
      if (parts.length < 4) {
        cur = null;
        continue;
      }
      cur = { name: parts[1], email: parts[2], date: parts[3] };
      continue;
    }
    if (!cur) continue;
    const file = line.trim();
    if (!file) continue;
    let arr = index.get(file);
    if (!arr) {
      arr = [];
      index.set(file, arr);
    }
    if (arr.length >= count) continue;
    if (arr.some((c) => c.email === cur!.email)) continue;
    arr.push(cur);
  }
  return index;
}

interface EnrichProgress {
  type: "file" | "complete";
  message: string;
  current?: number;
  total?: number;
}

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  HIGH_BUG: 2,
  MEDIUM: 3,
  BUG: 4,
  LOW: 5,
};

export async function enrich(params: {
  projectId: string;
  filter?: string;
  force?: boolean;
  concurrency?: number;
  /** Only enrich files that have at least one finding at this severity or above */
  minSeverity?: Severity;
  onProgress?: (progress: EnrichProgress) => void;
}): Promise<{ enriched: number }> {
  const {
    projectId,
    filter,
    force = false,
    concurrency = defaultConcurrency(),
    minSeverity,
  } = params;
  const project = readProjectConfig(projectId);
  const records = loadAllFileRecords(projectId);

  const ownershipProvider = getRegistry().ownership;
  const repo = ownershipProvider ? getRepoFromGitRemote(project.rootPath) : null;

  // Only enrich files with findings (optionally gated by severity)
  const toEnrich = records.filter((r) => {
    if (r.findings.length === 0) return false;
    if (filter && !r.filePath.startsWith(filter)) return false;
    if (!force && r.gitInfo) return false;
    if (minSeverity) {
      const minIdx = SEVERITY_ORDER[minSeverity];
      const hasQualifying = r.findings.some((f) => SEVERITY_ORDER[f.severity] <= minIdx);
      if (!hasQualifying) return false;
    }
    return true;
  });

  let enriched = 0;
  const total = toEnrich.length;

  // Build the per-file committer index once via a single git log invocation.
  // This is a 100x+ speedup over per-file `git log` shell-outs on large repos.
  // If the repo isn't a git checkout (e.g. sandbox upload stripped .git), the
  // index is empty and committers fall back to the empty array — same as the
  // per-file failure path used to do.
  const gitStart = Date.now();
  const committerIndex = buildGitCommitterIndex(project.rootPath, {
    since: "2 years ago",
    count: 5,
  });
  try {
    params.onProgress?.({
      type: "file",
      message: `Built git committer index: ${committerIndex.size} files in ${((Date.now() - gitStart) / 1000).toFixed(1)}s`,
      current: 0,
      total,
    });
  } catch {}

  async function enrichOne(record: FileRecord): Promise<void> {
    const committers = committerIndex.get(record.filePath) ?? [];
    const previousOwnership = record.gitInfo?.ownership;

    record.gitInfo = {
      recentCommitters: committers,
      enrichedAt: new Date().toISOString(),
      ownership: previousOwnership,
    };

    if (ownershipProvider && repo) {
      const ownership = await ownershipProvider.fetchOwnership({
        filePath: record.filePath,
        repo,
      });
      if (ownership) {
        record.gitInfo.ownership = ownership;
      }
    }

    writeFileRecord(record);
    enriched++;

    const ownershipStatus = record.gitInfo.ownership
      ? `${record.gitInfo.ownership.contributors.length} owner(s)`
      : "git only";

    try {
      params.onProgress?.({
        type: "file",
        message: `${record.filePath} — ${committers.length} committer(s), ${ownershipStatus}`,
        current: enriched,
        total,
      });
    } catch {}
  }

  // Process with concurrency
  if (concurrency <= 1) {
    for (const record of toEnrich) {
      await enrichOne(record);
    }
  } else {
    let idx = 0;
    async function worker(): Promise<void> {
      while (idx < toEnrich.length) {
        const record = toEnrich[idx++];
        await enrichOne(record);
      }
    }
    await Promise.all(
      Array.from({ length: Math.min(concurrency, toEnrich.length) }, () => worker()),
    );
  }

  try {
    params.onProgress?.({
      type: "complete",
      message: `Enriched ${enriched} files with git history${ownershipProvider && repo ? ` + ${ownershipProvider.name}` : ""}`,
    });
  } catch {}

  return { enriched };
}

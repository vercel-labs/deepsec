import fs from "node:fs";
import path from "node:path";
import {
  type AnalysisEntry,
  assertSafeFilePath,
  type FileRecord,
  type Finding,
  fileRecordSchema,
} from "@deepsec/core";

/**
 * Tarball extraction is `cwd=dataDir(projectId)`, so file records live
 * under `<destDir>/files/**.json`. We only merge those — run metadata
 * (`runs/*.json`) is unique per runId, so the tar overwrite is safe there.
 */
const FILES_SUBDIR = "files";

/**
 * Snapshot all existing file records under `<destDir>/files/` into a map
 * keyed by their path relative to `destDir` (e.g. `"files/src/foo.ts.json"`).
 *
 * Called BEFORE tar extraction so we have the host's pre-extraction state
 * to merge against once the tarball lands.
 *
 * Best-effort: malformed JSON is skipped silently rather than aborting the
 * download — a corrupt host record shouldn't block a sandbox upload, and
 * the incoming version will replace it via the normal extract path.
 */
export function snapshotFileRecords(destDir: string): Map<string, FileRecord> {
  const out = new Map<string, FileRecord>();
  const filesRoot = path.join(destDir, FILES_SUBDIR);
  if (!fs.existsSync(filesRoot)) return out;

  const stack: string[] = [filesRoot];
  while (stack.length > 0) {
    const dir = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        stack.push(full);
      } else if (e.isFile() && e.name.endsWith(".json")) {
        try {
          const raw = JSON.parse(fs.readFileSync(full, "utf-8"));
          out.set(path.relative(destDir, full), raw as FileRecord);
        } catch {
          // skip malformed
        }
      }
    }
  }
  return out;
}

/**
 * Merge two FileRecords representing the same file but written by
 * concurrent sandbox uploads.
 *
 * The race we're fixing: sandbox A and sandbox B both snapshotted the
 * host data dir at slightly different times. Each appended its own
 * `analysisHistory` entry locally, then uploaded a full tarball. Without
 * merging, whichever tarball is extracted last overwrites the other's
 * history — and in practice we observed entire codex runs disappearing
 * from per-file `analysisHistory` despite being recorded in `runs/*.json`.
 *
 * Merge strategy:
 *   - `analysisHistory`: union by `runId` (each run is globally unique).
 *     For the same runId on both sides, prefer `incoming` since the
 *     tarball is the more recent serialization.
 *   - `findings`: union by `(vulnSlug, normalized title)` signature, the
 *     same key `process()` uses to dedupe re-runs. For matching findings,
 *     merge field-by-field so a `revalidation` / `triage` set on either
 *     side survives.
 *   - `gitInfo`: prefer whichever side has it set — enrich runs only
 *     populate, never clear, so losing it across an extract is real loss.
 *   - `status`: "analyzed" wins over anything else (a finished run on
 *     either side means the file is analyzed). Otherwise prefer incoming.
 *   - `lockedByRunId` / `lockedAt`: prefer incoming; the per-batch loop
 *     in `process()` is the authoritative writer.
 *   - Scan-time fields (`candidates`, `lastScannedAt`, `lastScannedRunId`,
 *     `fileHash`): prefer incoming. Concurrent process/revalidate runs
 *     don't touch these — if they differ, the difference came from a
 *     scan run that has its own non-racing lifecycle.
 */
export function mergeFileRecord(host: FileRecord, incoming: FileRecord): FileRecord {
  const historyByRunId = new Map<string, AnalysisEntry>();
  for (const entry of host.analysisHistory ?? []) {
    historyByRunId.set(entry.runId, entry);
  }
  for (const entry of incoming.analysisHistory ?? []) {
    historyByRunId.set(entry.runId, entry);
  }
  const mergedHistory = Array.from(historyByRunId.values()).sort(
    (a, b) => new Date(a.investigatedAt).getTime() - new Date(b.investigatedAt).getTime(),
  );

  const findingsBySig = new Map<string, Finding>();
  for (const f of host.findings ?? []) {
    findingsBySig.set(findingSignature(f), f);
  }
  for (const f of incoming.findings ?? []) {
    const sig = findingSignature(f);
    const existing = findingsBySig.get(sig);
    findingsBySig.set(sig, existing ? mergeFinding(existing, f) : f);
  }
  const mergedFindings = Array.from(findingsBySig.values());

  const status =
    host.status === "analyzed" || incoming.status === "analyzed" ? "analyzed" : incoming.status;

  return {
    ...incoming,
    gitInfo: incoming.gitInfo ?? host.gitInfo,
    findings: mergedFindings,
    analysisHistory: mergedHistory,
    status,
  };
}

function findingSignature(f: Finding): string {
  return `${f.vulnSlug ?? ""}::${(f.title ?? "").trim().toLowerCase()}`;
}

function mergeFinding(host: Finding, incoming: Finding): Finding {
  return {
    ...host,
    ...incoming,
    revalidation: incoming.revalidation ?? host.revalidation,
    triage: incoming.triage ?? host.triage,
    producedByRunId: host.producedByRunId ?? incoming.producedByRunId,
  };
}

/**
 * After tar extraction, walk `<destDir>/files/**.json` and re-write any
 * record that also existed in `hostSnapshot` with a merged version.
 *
 * Sandbox output is the trust boundary, so every incoming record must:
 *   - parse as JSON
 *   - match `fileRecordSchema` exactly
 *   - declare the same `projectId` as the destDir's basename
 *   - declare a `filePath` whose serialized form matches the tarball entry
 *     path (`files/<filePath>.json`)
 *
 * If any of those checks fail on a record that *also* existed on the host,
 * we restore the host's version on disk — better an out-of-date but valid
 * record than a corrupted/spoofed one. If the failing record didn't exist
 * on the host, we delete it (the sandbox didn't have a legitimate need to
 * write a malformed record there).
 *
 * Files that didn't exist on the host before extraction and pass validation
 * are left untouched (they're the sandbox's contribution). Files that
 * existed on the host but are missing from the tarball are also untouched
 * (the sandbox didn't change them this poll).
 *
 * Returns the number of records that were merge-rewritten.
 */
export function mergeAfterExtract(
  destDir: string,
  hostSnapshot: Map<string, FileRecord>,
  expectedProjectId?: string,
): number {
  const filesRoot = path.join(destDir, FILES_SUBDIR);
  if (!fs.existsSync(filesRoot)) return 0;
  const requireProjectId = expectedProjectId ?? path.basename(destDir);

  let merged = 0;
  const stack: string[] = [filesRoot];
  while (stack.length > 0) {
    const dir = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        stack.push(full);
        continue;
      }
      if (!(e.isFile() && e.name.endsWith(".json"))) continue;
      const rel = path.relative(destDir, full);
      const host = hostSnapshot.get(rel);

      let raw: unknown;
      try {
        raw = JSON.parse(fs.readFileSync(full, "utf-8"));
      } catch {
        // Malformed JSON — restore host snapshot if we have one, else drop.
        restoreOrDrop(full, host);
        continue;
      }

      const parsed = fileRecordSchema.safeParse(raw);
      if (!parsed.success) {
        restoreOrDrop(full, host);
        continue;
      }
      const incoming = parsed.data;
      try {
        assertSafeFilePath(incoming.filePath);
      } catch {
        restoreOrDrop(full, host);
        continue;
      }

      // Sandbox tarball came from `data/<projectId>/`, so every record in
      // it must claim that same projectId, and the on-disk path must match
      // its declared filePath.
      const expectedRel = path
        .join(FILES_SUBDIR, `${incoming.filePath}.json`)
        .replaceAll("\\", "/");
      if (incoming.projectId !== requireProjectId || rel.replaceAll("\\", "/") !== expectedRel) {
        restoreOrDrop(full, host);
        continue;
      }

      if (!host) continue;
      const out = mergeFileRecord(host, incoming);
      fs.writeFileSync(full, JSON.stringify(out, null, 2) + "\n");
      merged++;
    }
  }
  return merged;
}

function restoreOrDrop(full: string, host: FileRecord | undefined): void {
  if (host) {
    try {
      fs.writeFileSync(full, JSON.stringify(host, null, 2) + "\n");
    } catch {}
    return;
  }
  try {
    fs.unlinkSync(full);
  } catch {}
}

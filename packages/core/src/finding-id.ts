import crypto from "node:crypto";
import type { FileRecord } from "./types.js";

/**
 * Deterministic, stable identifier for a finding. Derived ONLY from
 * immutable identifying data (projectId, normalized filePath, original
 * title) — never from severity, description, line numbers, or
 * revalidation state — so the same finding gets the same ID on every
 * load, across scans and revalidation runs, on any machine.
 *
 * The ID is what the revalidation agent echoes back to identify a
 * finding, so it stays short: `finding_` + first 16 hex chars of the
 * sha256 (64 bits — collision within a single project's finding count
 * is negligible, and same-file collisions are handled explicitly in
 * `ensureFindingIds`).
 */
export function computeFindingId(projectId: string, filePath: string, title: string): string {
  const normPath = filePath.replaceAll("\\", "/").replace(/^\.\//, "");
  const h = crypto.createHash("sha256").update(`${projectId}\0${normPath}\0${title}`).digest("hex");
  return `finding_${h.slice(0, 16)}`;
}

/**
 * Lazily backfill `findingId` on every finding of a record that predates
 * the field. Mutates in place; returns true when anything was assigned.
 *
 * Deterministic across loads: IDs are derived from immutable fields, and
 * two same-file findings with the *identical* title (rare, but the
 * investigate-merge dedup only suppresses same slug+title, so distinct
 * slugs can collide on title) are disambiguated by a stable ordinal that
 * follows array order — findings are append-only, so the ordinal never
 * changes for an existing finding.
 *
 * Callers on the read path (readFileRecord / loadAllFileRecords) backfill
 * in memory only; the IDs persist the next time the record is written,
 * and re-deriving on every load yields the same values until then.
 */
export function ensureFindingIds(record: FileRecord): boolean {
  let changed = false;
  const used = new Set<string>();
  for (const f of record.findings) {
    if (f.findingId) used.add(f.findingId);
  }
  for (const f of record.findings) {
    if (f.findingId) continue;
    let id = computeFindingId(record.projectId, record.filePath, f.title);
    // Same-file title collision: salt with a stable ordinal until unique.
    for (let n = 2; used.has(id); n++) {
      id = computeFindingId(record.projectId, record.filePath, `${f.title}\0${n}`);
    }
    used.add(id);
    f.findingId = id;
    changed = true;
  }
  return changed;
}

import type { FileRecord, Finding } from "@deepsec/core";
import { ensureFindingIds } from "@deepsec/core";
import type { RevalidateVerdict } from "./agents/types.js";

/**
 * Reconciliation layer between "what the agent returned" and "which stored
 * finding it meant". Agents reproduce identifiers stochastically — titles
 * get re-worded, backticks appear, paths gain a leading `./` — and the
 * previous exact filePath+title equality silently discarded any verdict
 * that didn't match byte-for-byte. This module matches permissively but
 * deterministically, never guessing when more than one finding remains
 * plausible.
 */

/** The identity of one finding we asked the agent to revalidate. */
export interface ExpectedFinding {
  findingId: string;
  filePath: string;
  title: string;
  /**
   * Short per-invocation alias (`F1`, `F2`, …) — the ID the prompt shows
   * and the model is asked to echo back. Two characters are far harder
   * to mangle than a 16-hex hash. Assigned in prompt order by
   * `expectedFindingsForBatch`; storage identity remains `findingId`.
   */
  alias?: string;
}

/**
 * Normalize an identifier the model returned for alias comparison:
 * accepts `F3`, `f3`, `#3`, `F 3`, and bare `3` — all normalize to "3".
 * Returns undefined for anything that isn't an alias-shaped token, so a
 * real `finding_…` ID or a title never accidentally alias-matches.
 */
export function normalizeAliasRef(s: string): string | undefined {
  const m = s.trim().match(/^#?\s*[Ff]?\s*(\d{1,4})$/);
  return m ? String(Number(m[1])) : undefined;
}

function aliasKey(alias: string | undefined): string | undefined {
  if (!alias) return undefined;
  return normalizeAliasRef(alias);
}

export type MatchedBy = "finding-id" | "exact-title" | "normalized-title" | "unique-remainder";

export interface ReconcileDiagnostic {
  matchedBy: MatchedBy;
  returnedFindingId?: string;
  returnedTitle?: string;
  returnedFilePath?: string;
  resolvedFindingId: string;
}

export interface ReconcileMatch {
  expected: ExpectedFinding;
  verdict: RevalidateVerdict;
  diagnostic: ReconcileDiagnostic;
}

export interface ReconcileResult {
  matches: ReconcileMatch[];
  /** Expected findings that received no verdict. */
  missing: ExpectedFinding[];
  /** Verdicts whose identifiers matched no expected finding. */
  unknown: RevalidateVerdict[];
  /**
   * Verdicts whose normalized identifiers matched MORE than one expected
   * finding. Never applied — they go to repair, not to a guess.
   */
  ambiguous: RevalidateVerdict[];
}

export function normalizePath(p: string): string {
  return p.replaceAll("\\", "/").replace(/^\.\//, "").trim();
}

/**
 * Title normalization for fallback matching: Unicode NFKC, Markdown
 * quoting/backticks stripped, whitespace collapsed, case-insensitive,
 * trailing sentence punctuation dropped.
 */
export function normalizeTitle(t: string): string {
  return t
    .normalize("NFKC")
    .replace(/[`*_"'‘’“”]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase()
    .replace(/[.,:;!?]+$/, "");
}

/**
 * The exact set of findings a revalidation prompt asks about: unrevalidated
 * (or all, under force), optionally restricted to an explicit findingId
 * subset (used by the adaptive-split retries so already-persisted verdicts
 * are never re-requested). Mirrors the filter in buildRevalidatePrompt —
 * the two MUST stay in sync so reconciliation expects exactly what the
 * prompt asked for.
 */
export function expectedFindingsForBatch(
  batch: FileRecord[],
  opts: { force?: boolean; onlyFindingIds?: ReadonlySet<string> } = {},
): ExpectedFinding[] {
  const expected: ExpectedFinding[] = [];
  for (const file of batch) {
    ensureFindingIds(file);
    for (const f of file.findings) {
      if (!shouldRevalidateFinding(f, opts)) continue;
      expected.push({
        findingId: f.findingId!,
        filePath: file.filePath,
        title: f.title,
        // Short prompt-facing alias, assigned in iteration order. The
        // prompt builder and the processor both derive expectations from
        // this function with identical inputs, so the alias→findingId
        // mapping is consistent across the prompt, the plugin's repair
        // loop, and the processor's reconciliation.
        alias: `F${expected.length + 1}`,
      });
    }
  }
  return expected;
}

export function shouldRevalidateFinding(
  f: Finding,
  opts: { force?: boolean; onlyFindingIds?: ReadonlySet<string> },
): boolean {
  if (opts.onlyFindingIds) {
    return f.findingId !== undefined && opts.onlyFindingIds.has(f.findingId);
  }
  return opts.force ? true : !f.revalidation;
}

/**
 * Match verdicts to expected findings, most-deterministic rule first:
 *
 *   1. exact findingId, or the finding's short alias (`F3` / `f3` /
 *      `#3` / `3`)
 *   2. exact title within the exact (path-normalized) file — the legacy
 *      contract, kept for old agents/responses
 *   3. normalized title within the exact file
 *   4. unique remainder — exactly one unmatched verdict AND one unmatched
 *      finding left in the batch
 *
 * Each finding gets at most one verdict (first match in verdict order
 * wins); each verdict resolves to at most one finding. A verdict that
 * would match multiple findings under a rule is ambiguous and is NOT
 * applied.
 */
export function reconcileVerdicts(
  expected: ExpectedFinding[],
  verdicts: RevalidateVerdict[],
): ReconcileResult {
  const matches: ReconcileMatch[] = [];
  const unmatchedExpected = new Set(expected);
  const remaining: RevalidateVerdict[] = [];
  const ambiguous: RevalidateVerdict[] = [];

  const record = (exp: ExpectedFinding, verdict: RevalidateVerdict, matchedBy: MatchedBy) => {
    unmatchedExpected.delete(exp);
    matches.push({
      expected: exp,
      verdict,
      diagnostic: {
        matchedBy,
        returnedFindingId: verdict.findingId,
        returnedTitle: verdict.title,
        returnedFilePath: verdict.filePath,
        resolvedFindingId: exp.findingId,
      },
    });
  };

  // Pass 1: exact findingId, or the short alias the prompt displayed.
  for (const v of verdicts) {
    const id = typeof v.findingId === "string" ? v.findingId.trim() : undefined;
    let exp: ExpectedFinding | undefined;
    if (id) {
      exp = [...unmatchedExpected].find((e) => e.findingId === id);
      if (!exp) {
        const refKey = normalizeAliasRef(id);
        if (refKey !== undefined) {
          exp = [...unmatchedExpected].find((e) => aliasKey(e.alias) === refKey);
        }
      }
    }
    if (exp) record(exp, v, "finding-id");
    else remaining.push(v);
  }

  // Pass 2: exact title within the exact file (legacy contract).
  let pass2Remaining: RevalidateVerdict[] = [];
  for (const v of remaining) {
    if (typeof v.filePath !== "string" || typeof v.title !== "string") {
      pass2Remaining.push(v);
      continue;
    }
    const vPath = normalizePath(v.filePath);
    const candidates = [...unmatchedExpected].filter(
      (e) => normalizePath(e.filePath) === vPath && e.title === v.title,
    );
    if (candidates.length === 1) record(candidates[0], v, "exact-title");
    else if (candidates.length > 1) ambiguous.push(v);
    else pass2Remaining.push(v);
  }

  // Pass 3: normalized title within the exact file.
  const pass3Remaining: RevalidateVerdict[] = [];
  for (const v of pass2Remaining) {
    if (typeof v.filePath !== "string" || typeof v.title !== "string") {
      pass3Remaining.push(v);
      continue;
    }
    const vPath = normalizePath(v.filePath);
    const vTitle = normalizeTitle(v.title);
    const candidates = [...unmatchedExpected].filter(
      (e) => normalizePath(e.filePath) === vPath && normalizeTitle(e.title) === vTitle,
    );
    if (candidates.length === 1) record(candidates[0], v, "normalized-title");
    else if (candidates.length > 1) ambiguous.push(v);
    else pass3Remaining.push(v);
  }
  pass2Remaining = [];

  // Pass 4: unique one-to-one remainder recovery. Only when the entire
  // batch has exactly one unmatched verdict and one unmatched finding —
  // there is nothing else the verdict could mean.
  let unknown = pass3Remaining;
  if (pass3Remaining.length === 1 && ambiguous.length === 0 && unmatchedExpected.size === 1) {
    const exp = [...unmatchedExpected][0];
    record(exp, pass3Remaining[0], "unique-remainder");
    unknown = [];
  }

  return {
    matches,
    missing: expected.filter((e) => unmatchedExpected.has(e)),
    unknown,
    ambiguous,
  };
}

/**
 * Alias-lookup table for an invocation: normalized alias key → findingId.
 * Used to translate a `duplicateOf` reference like "F2" back to the
 * stable id before resolution.
 */
export function buildAliasMap(expected: ExpectedFinding[]): Map<string, string> {
  const map = new Map<string, string>();
  for (const e of expected) {
    const key = aliasKey(e.alias);
    if (key !== undefined) map.set(key, e.findingId);
  }
  return map;
}

/**
 * Resolve a `duplicateOf` reference against the findings of its file (or,
 * when `crossFile` is enabled, all files in the batch). Accepts a short
 * alias (via `aliasMap`), a findingId, or a title (exact, then
 * normalized). Returns the referenced Finding, or undefined when nothing
 * — or more than one thing — matches. Same never-guess rule as verdict
 * matching.
 */
export function resolveDuplicateRef(params: {
  ref: string;
  file: FileRecord;
  batch?: FileRecord[];
  crossFile?: boolean;
  /** From buildAliasMap — translates "F2"-style refs to findingIds. */
  aliasMap?: ReadonlyMap<string, string>;
}): { file: FileRecord; finding: Finding } | undefined {
  const { ref, file, batch, crossFile = false, aliasMap } = params;
  const scope: FileRecord[] = crossFile && batch ? batch : [file];
  let trimmed = ref.trim();

  // Alias translation first: "F2" → the stable findingId it was shown as.
  const refKey = normalizeAliasRef(trimmed);
  if (refKey !== undefined && aliasMap?.has(refKey)) {
    trimmed = aliasMap.get(refKey)!;
  }

  // findingId is globally unique — search the whole scope directly.
  for (const rec of scope) {
    const byId = rec.findings.find((f) => f.findingId === trimmed);
    if (byId) return { file: rec, finding: byId };
  }

  const byTitle = (match: (f: Finding) => boolean) => {
    const hits: Array<{ file: FileRecord; finding: Finding }> = [];
    for (const rec of scope) {
      for (const f of rec.findings) {
        if (match(f)) hits.push({ file: rec, finding: f });
      }
    }
    return hits.length === 1 ? hits[0] : undefined;
  };

  return (
    byTitle((f) => f.title === trimmed) ??
    byTitle((f) => normalizeTitle(f.title) === normalizeTitle(trimmed))
  );
}

import type { CandidateMatch } from "@deepsec/core";

export function isLaravelSkippablePath(filePath: string): boolean {
  return /(?:^|\/)(?:tests?|vendor)\/|(?:^|\/)database\/(?:migrations|seeders|factories)\//.test(
    filePath,
  );
}

/**
 * Any sign of authorization: gates, `can:`/`auth` middleware, authorize()
 * calls, a 403 abort, or a FormRequest type-hint (FormRequest `authorize()`
 * runs before the action). A plain `Request $r` does not count.
 */
const AUTH_MARKER =
  /\bauthorize\w*\s*\(|\bGate::|->(?:can|cannot)\s*\(|\bauthorizeResource\b|\bmiddleware\s*\(\s*['"](?:can:|auth)|#\[Authorize|\babort_(?:if|unless)\s*\([^;]*(?:\b403\b|->can\b|Gate::)|\b(?!Request\b)\w+Request\s+\$/;

function hasAuthMarker(content: string): boolean {
  return AUTH_MARKER.test(content);
}

// Class-wide authorization. Other middleware (throttle, guest, verified)
// authorizes nothing.
// ponytail: ignores only/except scoping; parse the middleware call if that hides real misses.
const CLASS_AUTH =
  /\bauthorizeResource\b|\$this->middleware\s*\(\s*['"](?:auth|can:)|new\s+Middleware\s*\(\s*['"](?:auth|can:)/;
const FUNCTION_DECL = /\bfunction\s+\w+\s*\(/;
// Attributes and docblocks sit above the method they belong to.
const PREAMBLE = /^\s*(?:#\[|\/\*\*|\*)/;

/**
 * 1-based lines of `action` methods whose own body has no authorization, so
 * an authorized store() can't hide an unprotected destroy(). A method runs
 * from its attributes/docblock to the next named function's.
 */
export function unauthorizedActions(content: string, action: RegExp): number[] {
  if (CLASS_AUTH.test(content)) return [];
  const lines = content.split("\n");
  return lines.flatMap((line, i) => {
    if (!action.test(line)) return [];
    let start = i;
    while (start > 0 && PREAMBLE.test(lines[start - 1])) start--;
    let end = i + 1;
    while (end < lines.length && !FUNCTION_DECL.test(lines[end])) end++;
    while (end > i + 1 && PREAMBLE.test(lines[end - 1])) end--;
    return hasAuthMarker(lines.slice(start, end).join("\n")) ? [] : [i + 1];
  });
}

/** One candidate for a set of 1-based hit lines, snippet around the first. */
export function linesMatch(slug: string, content: string, hits: number[], label: string) {
  if (hits.length === 0) return [];
  const lines = content.split("\n");
  const match: CandidateMatch = {
    vulnSlug: slug,
    lineNumbers: hits,
    snippet: lines.slice(Math.max(0, hits[0] - 3), hits[0] + 2).join("\n"),
    matchedPattern: label,
  };
  return [match];
}

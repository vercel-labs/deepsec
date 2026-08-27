import type { CandidateMatch } from "@deepsec/core";

const PROLOGUE_RE = /^(?:\s|\/\/[^\n]*\n?|\/\*[\s\S]*?\*\/)*/;

/**
 * True if `content` opens with the given module-level directive, allowing a
 * leading shebang and any line/block comments above it.
 */
export function hasFileDirective(content: string, directive: string): boolean {
  let body = content;
  if (body.startsWith("#!")) {
    const eol = body.indexOf("\n");
    body = eol === -1 ? "" : body.slice(eol + 1);
  }
  body = body.replace(PROLOGUE_RE, "");
  return body.startsWith(`"${directive}"`) || body.startsWith(`'${directive}'`);
}

/**
 * Helper to build a regex-based matcher.
 * For each pattern, scans every line and collects matches with surrounding context.
 */
export function regexMatcher(
  slug: string,
  patterns: { regex: RegExp; label: string }[],
  content: string,
): CandidateMatch[] {
  const lines = content.split("\n");
  const matches: CandidateMatch[] = [];

  for (const { regex, label } of patterns) {
    const hitLines: number[] = [];
    const snippets: string[] = [];

    for (let i = 0; i < lines.length; i++) {
      if (regex.test(lines[i])) {
        hitLines.push(i + 1); // 1-based
        const start = Math.max(0, i - 2);
        const end = Math.min(lines.length, i + 3);
        snippets.push(lines.slice(start, end).join("\n"));
      }
    }

    if (hitLines.length > 0) {
      matches.push({
        vulnSlug: slug,
        lineNumbers: hitLines,
        snippet: snippets[0], // first occurrence context
        matchedPattern: label,
      });
    }
  }

  return matches;
}

import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Comprehensive "use server" coverage. Any file with "use server" directive
 * has every exported function callable as a public POST endpoint.
 * This is the broadest net — flags every export, not just ones missing auth.
 */
export const allServerActionsMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "all-server-actions",
  description:
    'All "use server" exported functions — every export is a public POST endpoint (weak candidate)',
  filePatterns: ["**/*.{ts,tsx}"],
  requires: { tech: ["nextjs"] },
  examples: [
    `"use server";\nexport async function createUser(name: string) { return { name } }`,
    `'use server'\nexport function deleteAccount(id) { return { id } }`,
    `"use server";\nexport const updateProfile = async (data) => ({ ok: true })`,
    `'use server'\nexport let fetchData = (q) => q`,
    `export async function doThing(x) {\n  "use server";\n  return x\n}`,
    `export const archiveItem = async (id) => {\n  'use server'\n  return id\n}`,
    `"use server";\nexport async function getList() {\n  return []\n}\nexport function helper() {}`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];
    if (/content\/|docs\/|\.mdx?$/i.test(filePath)) return [];
    if (!/['"]use server['"]/.test(content)) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    const hasFileDirective = /^['"]use server['"]/.test(content.trim());

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Any exported function or const arrow
      const isExport =
        /export\s+(async\s+)?function\s+\w+/.test(line) ||
        /export\s+(const|let)\s+\w+\s*=\s*(async\s+)?\(/.test(line);
      if (!isExport) continue;

      // For non-file-level directives, check for inline "use server"
      const hasInlineDirective = i + 1 < lines.length && /['"]use server['"]/.test(lines[i + 1]);
      // Also check inside the function body (first ~5 lines)
      const hasBodyDirective =
        !hasInlineDirective &&
        lines.slice(i + 1, Math.min(lines.length, i + 6)).some((l) => /['"]use server['"]/.test(l));

      if (!hasFileDirective && !hasInlineDirective && !hasBodyDirective) continue;

      const start = Math.max(0, i - 1);
      const end = Math.min(lines.length, i + 4);

      // Extract function name
      const nameMatch = line.match(/(?:function|const|let)\s+(\w+)/);
      const name = nameMatch?.[1] ?? "anonymous";

      matches.push({
        vulnSlug: "all-server-actions",
        lineNumbers: [i + 1],
        snippet: lines.slice(start, end).join("\n"),
        matchedPattern: `Server Action export: ${name} — public POST endpoint (weak candidate)`,
      });
    }

    return matches;
  },
};

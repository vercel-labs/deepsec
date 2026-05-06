import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * 100% server action coverage. Every exported function from a 'use server'
 * file is a publicly callable POST endpoint. We flag ALL of them.
 */
export const serverActionMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "server-action",
  description: "Next.js Server Actions — every export is a publicly callable POST endpoint",
  filePatterns: [
    "**/app/**/actions.{ts,tsx}",
    "**/app/**/*action*.{ts,tsx}",
    "**/**/actions/**/*.{ts,tsx}",
    "**/components/**/*.{ts,tsx}",
    "**/lib/**/*.{ts,tsx}",
    "**/src/**/*.{ts,tsx}",
  ],
  requires: { tech: ["nextjs"] },
  examples: [
    `"use server";\nexport async function createPost(title: string) { return { title } }`,
    `'use server'\nexport function deleteRecord(id) { return id }`,
    `"use server";\nexport const updateUser = async (data) => ({ ok: true })`,
    `'use server'\nexport let saveDraft = (input) => input`,
    `export async function archiveItem(id) {\n  "use server";\n  return id\n}`,
    `export const submitForm = async (data) => {\n  'use server'\n  return data\n}`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];
    if (/content\/|docs\/|\.mdx?$/i.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    // File-level directive
    const hasFileDirective = /^['"]use server['"]/.test(content.trim());

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const isExportedFn = /export\s+(async\s+)?function\s+\w+/.test(line);
      const isExportedConst = /export\s+(const|let)\s+\w+\s*=\s*(async\s+)?\(/.test(line);
      if (!isExportedFn && !isExportedConst) continue;

      // Check for inline "use server" on the next line
      const hasInlineDirective = i + 1 < lines.length && /['"]use server['"]/.test(lines[i + 1]);

      if (!hasFileDirective && !hasInlineDirective) continue;

      const start = Math.max(0, i - 1);
      const end = Math.min(lines.length, i + 4);
      matches.push({
        vulnSlug: "server-action",
        lineNumbers: [i + 1],
        snippet: lines.slice(start, end).join("\n"),
        matchedPattern: hasInlineDirective
          ? "Server Action (inline 'use server') — publicly callable POST endpoint"
          : "Server Action (file-level 'use server') — publicly callable POST endpoint",
      });
    }

    return matches;
  },
};

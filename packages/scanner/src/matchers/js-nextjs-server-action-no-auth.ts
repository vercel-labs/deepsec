import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

export const serverActionNoAuthMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "server-action-no-auth",
  description:
    "Server Action exports without any auth call — every export is a public POST endpoint",
  filePatterns: ["**/*.{ts,tsx}"],
  requires: { tech: ["nextjs"] },
  examples: [
    `"use server";\nexport async function createUser(name: string) { return { name } }`,
    `'use server'\nexport function deleteAccount(id) { return id }`,
    `export async function doThing(x) {\n  "use server";\n  return x\n}`,
    `"use server";\nexport async function fetchSecret() {\n  return { secret: 'no auth call' }\n}`,
    `"use server";\nexport async function getProfile(id) {\n  const session = await getSession();\n  return { id, session }\n}`,
    `"use server";\nexport async function adminWipe() {\n  await requireAuth();\n  return { ok: true }\n}`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];
    if (/content\/|docs\/|\.mdx?$/i.test(filePath)) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    // File-level "use server"
    const hasFileDirective = /^['"]use server['"]/.test(content.trim());

    const authCalls = [
      /getSession\s*\(/,
      /auth\s*\(\s*\)/,
      /requireAuth/,
      /withAuth/,
      /verifyToken/,
      /authUserAndTeamByAuthAPI/,
      /isAuthenticated/,
      /assertAuth/,
      /checkAuth/,
      /parseAuthToken/,
      /withOidcTokenAuth/,
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Check for inline "use server" on the next line after export
      const isInlineServerAction =
        i + 1 < lines.length &&
        /['"]use server['"]/.test(lines[i + 1]) &&
        /export\s+(async\s+)?function/.test(line);

      const isFileExport = hasFileDirective && /export\s+(async\s+)?function\s+\w+/.test(line);

      if (!isInlineServerAction && !isFileExport) continue;

      // Check if this function has any auth call in its body (next 30 lines)
      const fnBody = lines.slice(i, Math.min(lines.length, i + 30)).join("\n");
      const hasAuth = authCalls.some((p) => p.test(fnBody));

      const start = Math.max(0, i - 1);
      const end = Math.min(lines.length, i + 4);
      matches.push({
        vulnSlug: "server-action-no-auth",
        lineNumbers: [i + 1],
        snippet: lines.slice(start, end).join("\n"),
        matchedPattern: hasAuth
          ? "Server Action with auth call (verify correctness)"
          : "Server Action WITHOUT any auth call — publicly callable",
      });
    }

    return matches;
  },
};

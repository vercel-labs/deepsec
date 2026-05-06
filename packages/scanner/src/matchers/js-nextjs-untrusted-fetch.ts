import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Framework code where a `fetch(...)` call's URL originates from a request
 * (`req.url`, headers, query, body) without an obvious allow-list check. The
 * Next.js image optimizer SSRF class lives here.
 *
 * Differs from the generic `ssrf` matcher: it specifically looks at FRAMEWORK
 * code (anything under `packages/next/src/server`, `packages/next-server`,
 * `packages/next/src/lib`, or any file with both an HTTP-handler signature
 * and a `fetch` call to a non-literal URL).
 */
export const frameworkUntrustedFetchMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "framework-untrusted-fetch",
  description: "Framework code calling fetch with a URL derived from request input",
  filePatterns: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.mjs"],
  requires: { tech: ["nextjs"] },
  examples: [
    `const url = req.url;\nconst res = await fetch(url);`,
    `const target = request.headers.get('x-target');\nconst data = await fetch(target);`,
    `const u = new URL(req.url);\nawait fetch(u.searchParams.get('href'));`,
    `const upstream = req.query.upstream;\nawait globalThis.fetch(upstream);`,
    `const path = request.nextUrl.searchParams.get('path');\nconst r = await fetch(path);`,
    `const meta = getRequestMeta(req, 'origin');\nconst r = await fetch(meta + '/api');`,
    `const cookieVal = request.cookies.get('redirect')?.value;\nconst r = await fetch(cookieVal);`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)$/.test(filePath)) return [];
    if (/\.d\.ts$/.test(filePath)) return [];

    // Restrict to plausible framework internals
    const isFrameworkPath =
      /(?:^|\/)packages\/(?:next|next-server|next-mdx|next-codemod|next-bundle-analyzer)\/src\//.test(
        filePath,
      ) ||
      /(?:^|\/)src\/server\//.test(filePath) ||
      /(?:^|\/)src\/lib\/router-utils\//.test(filePath);
    if (!isFrameworkPath) return [];

    const lines = content.split("\n");
    const hitLines: number[] = [];
    let firstContext: string | undefined;

    const FETCH_LINE = /\b(?:globalThis\.|window\.)?fetch\s*\(/;
    const TAINT_HINTS =
      /\b(?:req\.(?:url|query|headers|body)|request\.(?:url|nextUrl|headers|query|body)|searchParams\.get\b|new\s+URL\s*\(\s*req\b|nextUrl\.(?:searchParams|pathname)|getRequestMeta\b|request\.cookies)/;

    for (let i = 0; i < lines.length; i++) {
      if (!FETCH_LINE.test(lines[i])) continue;
      // Look at -8 / +5 lines for the URL source
      const span = lines.slice(Math.max(0, i - 8), Math.min(lines.length, i + 6)).join("\n");
      if (!TAINT_HINTS.test(span)) continue;
      hitLines.push(i + 1);
      if (firstContext === undefined) {
        const s = Math.max(0, i - 3);
        const e = Math.min(lines.length, i + 4);
        firstContext = lines.slice(s, e).join("\n");
      }
    }

    if (hitLines.length === 0) return [];
    const match: CandidateMatch = {
      vulnSlug: "framework-untrusted-fetch",
      lineNumbers: hitLines,
      snippet: firstContext ?? "",
      matchedPattern: "fetch in framework code with URL from req/headers/query/body",
    };
    return [match];
  },
};

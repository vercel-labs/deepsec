import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Any code path that handles a Next.js internal header. The framework uses
 * a class of `x-middleware-*` / `x-next-*` / `__Next-*` headers to coordinate
 * between server, middleware, and the rendered page. None of these should
 * EVER be readable from an incoming user request — they must be stripped
 * server-side before being trusted.
 *
 * CVE-2025-29927 was a middleware-bypass via `x-middleware-subrequest`. This
 * matcher flags every site for human/AI review.
 */
export const frameworkInternalHeaderMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "framework-internal-header",
  description: "Reads/writes of Next.js internal headers (x-middleware-*, x-next-*, __Next-*)",
  filePatterns: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.mjs"],
  requires: { tech: ["nextjs"] },
  examples: [
    `const subreq = headers.get('x-middleware-subrequest');`,
    `res.headers.set('x-middleware-rewrite', target);`,
    `res.headers.set('x-middleware-redirect', loc);`,
    `if (req.headers.get('x-middleware-prefetch')) return;`,
    `headers['x-next-prerender-bypass'] = token;`,
    `const tags = res.headers.get('x-next-cache-tags');`,
    `if (req.headers['__Next-Action']) handle();`,
    `const id = req.headers.get('next-action-id');`,
    `const tree = req.headers.get('next-router-state-tree');`,
    `if (req.headers.get('rsc')) return rscResponse();`,
    `const original = req.headers.get('next-url');`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)$/.test(filePath)) return [];
    if (/\.d\.ts$/.test(filePath)) return [];

    const lines = content.split("\n");
    const hitLines: number[] = [];
    const labels = new Set<string>();
    let firstContext: string | undefined;

    const HEADERS = [
      "x-middleware-subrequest",
      "x-middleware-prefetch",
      "x-middleware-rewrite",
      "x-middleware-redirect",
      "x-middleware-next",
      "x-middleware-cookie",
      "x-middleware-set-cookie",
      "x-middleware-override-headers",
      "x-middleware-skip",
      "x-next-prerender-bypass",
      "x-next-revalidated-tags",
      "x-next-cache-tags",
      "x-next-debug-logging",
      "__Next-Action",
      "next-action-id",
      "next-router-state-tree",
      "next-router-prefetch",
      "next-router-segment-prefetch",
      "rsc",
      "next-url",
    ];
    const re = new RegExp(
      `['"\`](${HEADERS.map((h) => h.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&")).join("|")})['"\`]`,
      "i",
    );

    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(re);
      if (!m) continue;
      hitLines.push(i + 1);
      labels.add(m[1].toLowerCase());
      if (firstContext === undefined) {
        const s = Math.max(0, i - 2);
        const e = Math.min(lines.length, i + 3);
        firstContext = lines.slice(s, e).join("\n");
      }
    }

    if (hitLines.length === 0) return [];
    const match: CandidateMatch = {
      vulnSlug: "framework-internal-header",
      lineNumbers: hitLines,
      snippet: firstContext ?? "",
      matchedPattern: Array.from(labels).slice(0, 4).join(", "),
    };
    return [match];
  },
};

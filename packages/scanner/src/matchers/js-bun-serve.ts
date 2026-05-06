import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const jsBunServeMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "js-bun-serve",
  description: "Bun.serve fetch handlers — entry-point surface (gated on bun)",
  filePatterns: ["**/*.{ts,js,mjs}"],
  requires: { tech: ["bun"] },
  examples: [
    `Bun.serve({\n  fetch(req) { return new Response("hi") }\n})`,
    `Bun.serve({ port: 3000, async fetch(req) { return new Response() } })`,
    `async fetch(req) { return new Response("ok") }`,
    `fetch(request, server) { return new Response() }`,
    `const url = request.url`,
    `const method = request.method`,
    `const auth = request.headers.get("authorization")`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    return regexMatcher(
      "js-bun-serve",
      [
        { regex: /\bBun\.serve\s*\(\s*\{/, label: "Bun.serve({ fetch(req) ... })" },
        {
          regex: /(?:async\s+)?fetch\s*\(\s*req(?:uest)?\s*[,)]/,
          label: "fetch(req) handler body",
        },
        { regex: /\brequest\.(?:url|headers|method)\b/, label: "request.* accessor" },
      ],
      content,
    );
  },
};

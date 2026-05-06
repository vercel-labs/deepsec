import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const jsDenoRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "js-deno-route",
  description: "Deno HTTP server / Oak router handlers (gated on deno)",
  filePatterns: ["**/*.{ts,tsx}"],
  requires: { tech: ["deno"] },
  examples: [
    `Deno.serve((req) => new Response("hi"))`,
    `Deno.serve({ port: 8000 }, handler)`,
    `router.get("/users", (ctx) => {})`,
    `router.post('/api/users', createUser)`,
    `router.use(authMiddleware)`,
    `router.delete("/u/:id", removeUser)`,
    `import { Application, Router } from "https://deno.land/x/oak/mod.ts";`,
    `const url = ctx.request.url;`,
    `const body = await ctx.request.body().value`,
    `const auth = ctx.request.headers.get("Authorization")`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    return regexMatcher(
      "js-deno-route",
      [
        { regex: /\bDeno\.serve\s*\(/, label: "Deno.serve() entry point" },
        {
          regex: /\brouter\.(?:get|post|put|patch|delete|all|use)\s*\(/,
          label: "Oak router method",
        },
        {
          regex:
            /import\s*\{[^}]*\bApplication\b[^}]*\}\s*from\s*['"]https?:\/\/deno\.land\/x\/oak/,
          label: "Oak Application import",
        },
        { regex: /\bctx\.request\.(?:url|body|headers)\b/, label: "Oak ctx.request accessor" },
      ],
      content,
    );
  },
};

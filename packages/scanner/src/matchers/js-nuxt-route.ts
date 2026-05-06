import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const jsNuxtRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "js-nuxt-route",
  description: "Nuxt server routes / event handlers (gated on Nuxt)",
  filePatterns: ["**/server/api/**/*.{ts,js}", "**/server/routes/**/*.{ts,js}"],
  requires: { tech: ["nuxt"] },
  examples: [
    `export default defineEventHandler(async (event) => {})`,
    `export default eventHandler((event) => ({ ok: true }))`,
    `const id = getRouterParam(event, "id")`,
    `const params = getRouterParams(event)`,
    `const q = getQuery(event)`,
    `const body = await readBody(event)`,
    `throw createError({ statusCode: 401, message: "nope" })`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    return regexMatcher(
      "js-nuxt-route",
      [
        {
          regex: /\bdefineEventHandler\s*\(/,
          label: "defineEventHandler — Nuxt server entry point",
        },
        { regex: /\beventHandler\s*\(/, label: "h3 eventHandler factory" },
        {
          regex: /\bgetRouterParam(?:s)?\s*\(|\bgetQuery\s*\(|\breadBody\s*\(/,
          label: "h3 request accessor (untrusted input)",
        },
        { regex: /\bcreateError\s*\(/, label: "createError() throw site" },
      ],
      content,
    );
  },
};

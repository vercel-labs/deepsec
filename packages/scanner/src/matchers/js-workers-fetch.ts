import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const jsWorkersFetchMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "js-workers-fetch",
  description: "Cloudflare Workers / edge runtime default-export fetch handler (gated on workers)",
  filePatterns: ["**/*.{ts,js,mjs}"],
  requires: { tech: ["workers"] },
  examples: [
    `export default { async fetch(req, env, ctx) { return new Response("ok") } }`,
    `export default { fetch(request, env, ctx) { return new Response() } }`,
    `addEventListener('fetch', (event) => { event.respondWith(handle(event.request)) })`,
    `addEventListener("fetch", e => e.respondWith(handler(e.request)))`,
    `const value = await env.MY_KV.get("key")`,
    `const obj = env.R2_BUCKET`,
    `const secret = env.API_TOKEN`,
    `const cache = caches.default`,
    `const c = await caches.open("v1")`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    return regexMatcher(
      "js-workers-fetch",
      [
        {
          regex: /export\s+default\s*\{\s*(?:async\s+)?fetch\s*\(/,
          label: "Workers default export { fetch(req, env, ctx) }",
        },
        {
          regex: /addEventListener\s*\(\s*['"]fetch['"]/,
          label: "addEventListener('fetch', ...) — service worker",
        },
        {
          regex: /\benv\.[A-Z][A-Z0-9_]+/,
          label: "env.* binding access (KV, R2, secrets)",
        },
        {
          regex: /\bcaches\.default\b|\bcaches\.open\s*\(/,
          label: "Workers cache API — review key composition",
        },
      ],
      content,
    );
  },
};

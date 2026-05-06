import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const jsAstroEndpointMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "js-astro-endpoint",
  description: "Astro API endpoints and SSR routes (gated on Astro)",
  filePatterns: ["**/pages/**/*.{ts,js}", "**/pages/api/**/*.{ts,js}", "**/src/pages/**/*.astro"],
  requires: { tech: ["astro"] },
  examples: [
    `export const GET: APIRoute = async ({ request }) => {}`,
    `export async function POST({ request }) { return new Response(null) }`,
    `export const PUT = ({ request }) => {}`,
    `export function DELETE({ params }) {}`,
    `export const ALL: APIRoute = async ({ request }) => {}`,
    `const url = Astro.request.url`,
    `const token = Astro.cookies.get("session")`,
    `const id = Astro.params.id`,
    `export const prerender = false`,
    `cookies.set("session", value, { httpOnly: true })`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    return regexMatcher(
      "js-astro-endpoint",
      [
        {
          regex: /export\s+(?:async\s+)?(?:const|function)\s+(GET|POST|PUT|PATCH|DELETE|ALL)\b/,
          label: "Astro endpoint method export",
        },
        { regex: /\bAstro\.(?:request|cookies|params|url)\b/, label: "Astro.* request accessor" },
        { regex: /\bexport\s+const\s+prerender\s*=/, label: "prerender flag (SSR / SSG split)" },
        { regex: /\bSetCookie\s*\(|cookies\.set\s*\(/, label: "cookie write — auth surface" },
      ],
      content,
    );
  },
};

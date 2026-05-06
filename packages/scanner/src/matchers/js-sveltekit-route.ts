import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const jsSveltekitRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "js-sveltekit-route",
  description: "SvelteKit endpoint and load handlers (gated on SvelteKit)",
  filePatterns: ["**/+page.server.{ts,js}", "**/+server.{ts,js}", "**/+layout.server.{ts,js}"],
  requires: { tech: ["sveltekit"] },
  examples: [
    `export const GET = async ({ request }) => json({});`,
    `export async function POST({ request }) { return new Response(); }`,
    `export const PUT = async () => json({});`,
    `export async function DELETE({ params }) {}`,
    `export const load = async ({ locals }) => ({ user: locals.user });`,
    `export async function load({ params, fetch }) {}`,
    `export const actions = { default: async ({ request }) => {} };`,
    `throw redirect(302, "/login");`,
    `throw error(401, "unauthorized");`,
    `return fail(400, { message });`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    return regexMatcher(
      "js-sveltekit-route",
      [
        {
          regex:
            /export\s+(?:async\s+)?(?:const|function)\s+(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\b/,
          label: "+server method handler",
        },
        {
          regex: /export\s+(?:async\s+)?(?:const|function)\s+load\b/,
          label: "+page.server.ts / +layout.server.ts load function",
        },
        {
          regex: /export\s+const\s+actions\s*[:=]/,
          label: "+page.server.ts actions export (form actions)",
        },
        { regex: /\b(?:fail|redirect|error)\s*\(/, label: "SvelteKit response helper" },
      ],
      content,
    );
  },
};

import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const jsRemixRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "js-remix-route",
  description: "Remix route loaders and actions (gated on Remix)",
  filePatterns: ["**/app/routes/**/*.{ts,tsx,js,jsx}", "**/routes/**/*.{ts,tsx,js,jsx}"],
  requires: { tech: ["remix"] },
  examples: [
    `export const loader = async ({ request }) => json({});`,
    `export const action = async ({ request }) => redirect("/x");`,
    `export async function loader({ request }) { return json({}); }`,
    `export async function action({ request }) {}`,
    `export default function Route() { return null; }`,
    `return json({ user }, { headers: { "Set-Cookie": session } });`,
    `await requireUserId(request);`,
    `const userId = await requireUser(request);`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    return regexMatcher(
      "js-remix-route",
      [
        {
          regex: /export\s+(?:async\s+)?(?:const|function)\s+(?:loader|action)\b/,
          label: "Remix loader/action export",
        },
        {
          regex: /export\s+default\s+function\s+\w+/,
          label: "Remix default export route component",
        },
        {
          regex: /\bjson\s*\(\s*\{[^}]*\}\s*,\s*\{\s*headers/,
          label: "json() with custom headers (auth response)",
        },
        { regex: /\brequireUser(?:Id)?\s*\(/, label: "common Remix auth helper" },
      ],
      content,
    );
  },
};

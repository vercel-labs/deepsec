import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const jsHapiRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "js-hapi-route",
  description: "Hapi server.route configurations (gated on Hapi)",
  filePatterns: ["**/*.{ts,js,mjs,cjs}"],
  requires: { tech: ["hapi"] },
  examples: [
    `const server = Hapi.server({ port: 3000 });`,
    `server.route({ method: "GET", path: "/", handler });`,
    `server.route({\n  method: 'POST',\n  path: '/login',\n  handler,\n});`,
    `server.route({ method: "GET", path: "/x", options: { auth: false } });`,
    `options: { auth: 'jwt' }`,
    `strategy: "session"`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    return regexMatcher(
      "js-hapi-route",
      [
        {
          regex: /\bserver\.route\s*\(\s*\{/,
          label: "server.route({ method, path, handler })",
        },
        { regex: /Hapi\.server\s*\(/, label: "Hapi.server() init" },
        { regex: /options:\s*\{\s*auth:/, label: "route auth option (verify scope)" },
        { regex: /strategy\s*:\s*['"][^'"]+['"]/, label: "auth strategy declaration" },
      ],
      content,
    );
  },
};

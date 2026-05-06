import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const corsWildcardMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "cors-wildcard",
  description: "CORS wildcard or dynamic origin reflection without validation",
  filePatterns: ["**/*.{ts,tsx,js,jsx,lua,go,conf}"],
  examples: [
    `res.setHeader("Access-Control-Allow-Origin", "*");`,
    `headers: { "Access-Control-Allow-Origin": "*" }`,
    `res.setHeader("Access-Control-Allow-Origin", req.headers.origin);`,
    `headers["Access-Control-Allow-Origin"] = origin;`,
    `headers["Access-Control-Allow-Credentials"] = "true"; headers["Access-Control-Allow-Origin"] = origin;`,
    `app.use(cors({ origin: true, credentials: true }));`,
    `add_header Access-Control-Allow-Origin $http_origin;`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    return regexMatcher(
      "cors-wildcard",
      [
        { regex: /Access-Control-Allow-Origin.*\*/, label: "CORS wildcard origin" },
        {
          regex:
            /Access-Control-Allow-Origin.*req\.headers\.origin|Access-Control-Allow-Origin.*origin/,
          label: "CORS origin reflection (verify validation)",
        },
        {
          regex:
            /Access-Control-Allow-Credentials.*true.*Allow-Origin|Allow-Origin.*Allow-Credentials.*true/i,
          label: "CORS credentials + origin (dangerous combo)",
        },
        {
          regex: /cors\s*\(\s*\{.*origin:\s*true/,
          label: "CORS middleware with origin: true (reflects all)",
        },
        {
          regex: /add_header\s+Access-Control-Allow-Origin\s+\$http_origin/,
          label: "Nginx CORS origin reflection",
        },
      ],
      content,
    );
  },
};

import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

/**
 * API repo: Finds endpoints with `authStrategy: '__PUBLIC__'` or no auth strategy.
 * Public endpoints are high-value targets — they're accessible without authentication.
 */
export const publicEndpointMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "public-endpoint",
  description:
    "Endpoints with __PUBLIC__ auth strategy or no authentication — high-value investigation targets",
  filePatterns: [
    "**/apps/**/route.ts",
    "**/apps/**/route.*.ts",
    "**/services/**/endpoints/**/*.ts",
    "**/services/**/src/index.ts",
  ],
  examples: [
    `{ authStrategy: "__PUBLIC__" }`,
    `authStrategy: '__PUBLIC__',`,
    `{ authStrategy: "static" }`,
    `authStrategy: 'static',`,
    `{ authStrategy: "none" }`,
    `authStrategy: 'none',`,
  ],
  match(content, _filePath) {
    return regexMatcher(
      "public-endpoint",
      [
        { regex: /authStrategy:\s*['"]__PUBLIC__['"]/, label: "__PUBLIC__ auth strategy" },
        { regex: /authStrategy:\s*['"]static['"]/, label: "static auth strategy (header-based)" },
        { regex: /authStrategy:\s*['"]none['"]/, label: "no auth strategy" },
      ],
      content,
    );
  },
};

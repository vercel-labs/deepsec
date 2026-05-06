import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Flags all direct access to process.env variables.
 * Catches: hardcoded fallbacks, secret leaks to client, env-as-bool bugs,
 * missing env vars causing auth bypass, etc.
 */
export const processEnvAccessMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "process-env-access",
  description: "Direct process.env access — check for fallbacks, leaks, and misuse",
  filePatterns: ["**/*.{ts,tsx,js,jsx}", "**/*.lua", "**/*.go"],
  examples: [
    `const url = process.env.DATABASE_URL;`,
    `const key = process.env.API_KEY ?? "fallback";`,
    `if (process.env.NODE_ENV === "development") doStuff();`,
    `const cfg = process.env["MY_VAR"];`,
    `const secret = process.env['SESSION_SECRET'];`,
  ],
  match(content, filePath) {
    if (/\.(test|spec|mock|stub)\./i.test(filePath)) return [];
    if (/node_modules|\.next|dist\/|\.d\.ts$/.test(filePath)) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const envMatch = line.match(/process\.env\.(\w+)|process\.env\[['"](\w+)['"]\]/);
      if (!envMatch) continue;

      const varName = envMatch[1] || envMatch[2];
      const start = Math.max(0, i - 1);
      const end = Math.min(lines.length, i + 2);

      matches.push({
        vulnSlug: "process-env-access",
        lineNumbers: [i + 1],
        snippet: lines.slice(start, end).join("\n"),
        matchedPattern: `process.env.${varName}`,
      });
    }

    return matches;
  },
};

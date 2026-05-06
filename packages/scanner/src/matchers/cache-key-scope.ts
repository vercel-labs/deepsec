import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Detects cache keys that may not be scoped to user/team/project,
 * enabling cross-tenant cache poisoning or information disclosure.
 */
export const cacheKeyScopeMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "cache-key-scope",
  description: "Cache keys that may lack user/team scoping — cross-tenant risk",
  filePatterns: ["**/*.{ts,tsx,js,jsx}"],
  examples: [
    `const cached = await redis.get(\`feature:\${name}\`);`,
    `await redis.set(\`config:\${name}\`, value);`,
    `await redis.hget(\`map:\${k}\`, field);`,
    `await redis.hset(\`map:\${k}\`, field, value);`,
    `await redis.setex(\`token:\${name}\`, 60, value);`,
    `await redis.get("global-counter");`,
    `await redis.set("singleton", value);`,
    `await cache.get(\`feature:\${flag}\`);`,
    `await cache.set(\`feature:\${flag}\`, value);`,
    `cache.has(\`flag:\${name}\`);`,
    `cache.get("global-counter");`,
    `cache.set("singleton", payload);`,
    `const cacheKey = \`feature:\${name}\`;`,
    `const cache_key = \`feature:\${name}\`;`,
    `await store.get(\`feature:flag:\${id}\`);`,
  ],
  match(content, filePath) {
    if (/\.(test|spec|mock|stub)\./i.test(filePath)) return [];
    if (/node_modules|\.next|dist\//.test(filePath)) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    // Patterns that construct cache keys
    const cacheKeyPatterns: { regex: RegExp; label: string }[] = [
      { regex: /redis\.(get|set|hget|hset|setex)\s*\(\s*`/, label: "Redis template key" },
      { regex: /redis\.(get|set|hget|hset|setex)\s*\(\s*['"]/, label: "Redis string key" },
      { regex: /cache\.(get|set|has)\s*\(\s*`/, label: "cache template key" },
      { regex: /cache\.(get|set|has)\s*\(\s*['"]/, label: "cache string key" },
      { regex: /cacheKey\s*=\s*`/, label: "cacheKey template literal" },
      { regex: /cache_key\s*=\s*`/, label: "cache_key template literal" },
      { regex: /\.get\s*\(\s*`[^`]*:/, label: "KV get with colon-separated key" },
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const { regex, label } of cacheKeyPatterns) {
        if (regex.test(line)) {
          // Check if the key includes a user/team scoping variable
          const context = lines.slice(Math.max(0, i - 1), Math.min(lines.length, i + 2)).join("\n");
          const hasScope =
            /userId|user_id|teamId|team_id|ownerId|owner_id|auth\.|session\.|projectId|project_id/i.test(
              context,
            );
          if (!hasScope) {
            const start = Math.max(0, i - 2);
            const end = Math.min(lines.length, i + 3);
            matches.push({
              vulnSlug: "cache-key-scope",
              lineNumbers: [i + 1],
              snippet: lines.slice(start, end).join("\n"),
              matchedPattern: `${label} — no user/team scoping visible in key construction`,
            });
          }
          break;
        }
      }
    }

    return matches;
  },
};

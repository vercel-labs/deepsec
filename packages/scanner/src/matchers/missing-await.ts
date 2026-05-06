import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Detects function calls that return Promises but aren't awaited,
 * especially around locks, mutexes, transactions, and critical async ops.
 */
export const missingAwaitMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "missing-await",
  description: "Async calls that may be missing await — race conditions, lost errors",
  filePatterns: ["**/*.{ts,tsx,js,jsx}"],
  examples: [
    `withMutex(() => doStuff());`,
    `withUserMutex(() => updateUser(id));`,
    `withLock(key, () => criticalSection());`,
    `withDistributedLock(key, fn);`,
    `withTransaction(async (tx) => {
  await tx.user.update({ id });
});`,
    `withDbTransaction(fn);`,
    `redis.get("key");`,
    `redis.set(key, value);`,
    `prisma.user.findUnique({ where: { id } });`,
    `prisma.session.delete({ where: { id } });`,
    `db.users.findOne({ id });`,
    `db.posts.update({ id });`,
  ],
  match(content, filePath) {
    if (/\.(test|spec|mock|stub)\./i.test(filePath)) return [];
    if (/node_modules|\.next|dist\//.test(filePath)) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    // Patterns for critical async calls that should always be awaited
    const criticalPatterns = [
      { regex: /(?<!await\s)(?<!return\s)with\w*Mutex\s*\(/, label: "mutex without await" },
      { regex: /(?<!await\s)(?<!return\s)with\w*Lock\s*\(/, label: "lock without await" },
      {
        regex: /(?<!await\s)(?<!return\s)with\w*Transaction\s*\(/,
        label: "transaction without await",
      },
      { regex: /(?<!await\s)(?<!return\s)redis\.\w+\s*\(/, label: "redis call without await" },
      {
        regex: /(?<!await\s)(?<!return\s)prisma\.\w+\.\w+\s*\(/,
        label: "prisma call without await",
      },
      { regex: /(?<!await\s)(?<!return\s)db\.\w+\.\w+\s*\(/, label: "db call without await" },
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      // Skip comments
      if (line.startsWith("//") || line.startsWith("*")) continue;

      for (const { regex, label } of criticalPatterns) {
        if (regex.test(line)) {
          const start = Math.max(0, i - 2);
          const end = Math.min(lines.length, i + 3);
          matches.push({
            vulnSlug: "missing-await",
            lineNumbers: [i + 1],
            snippet: lines.slice(start, end).join("\n"),
            matchedPattern: label,
          });
          break;
        }
      }
    }

    return matches;
  },
};

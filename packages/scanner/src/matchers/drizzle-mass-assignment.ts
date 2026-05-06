import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Drizzle insert/update with `req.body` (or spread of it) directly into
 * `.values()` / `.set()`. Mass-assignment surface: caller sets columns the
 * UI never exposes (`internal_score`, `created_by_user_id`, `tier`,
 * `verified`, etc.).
 *
 * Flags:
 *   - `.values(req.body)` / `.values(body)` / `.values(payload)`
 *   - `.values({ ...req.body })` / `.values({ ...body })` / `.values({ ...input })`
 *   - `.set({ ...req.body })` / `.set(req.body)`
 */
export const drizzleMassAssignmentMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "drizzle-mass-assignment",
  description: "Drizzle insert/update spreading request body — column-level mass assignment risk",
  filePatterns: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.mjs"],
  requires: { tech: ["drizzle"] },
  examples: [
    `import { users } from "drizzle-orm";\nawait db.insert(users).values(req.body);`,
    `import { users } from "drizzle-orm";\nawait db.insert(users).values({ ...req.body });`,
    `import { posts } from "drizzle-orm";\nawait db.insert(posts).values(payload);`,
    `import { posts } from "drizzle-orm";\nawait db.insert(posts).values({ ...input });`,
    `import { users } from "drizzle-orm";\nawait db.update(users).set(body);`,
    `import { users } from "drizzle-orm";\nawait db.update(users).set({ ...request.body });`,
    `import { users } from "@repo/db";\nawait db.insert(users).values({ ...formData });`,
    `import { users } from "drizzle-orm";\nawait db.update(users).set({ ...data });`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)$/.test(filePath)) return [];
    if (/\.d\.ts$/.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    const HAS_DRIZZLE = /\bfrom\s+["'](?:drizzle-orm[^"']*|@repo\/db[^"']*)["']/;
    if (!HAS_DRIZZLE.test(content)) return [];

    const lines = content.split("\n");
    const matches: CandidateMatch[] = [];

    // Variable names that strongly signal "untrusted incoming payload"
    const UNTRUSTED = /(?:req(?:uest)?\.body|body|payload|input|formData|data|json|args|params)/;

    const PATTERNS: { regex: RegExp; label: string }[] = [
      {
        regex: new RegExp(`\\.values\\s*\\(\\s*${UNTRUSTED.source}\\s*\\)`),
        label: ".values(untrusted) — direct mass assignment",
      },
      {
        regex: new RegExp(`\\.values\\s*\\(\\s*\\{\\s*\\.\\.\\.${UNTRUSTED.source}\\b`),
        label: ".values({ ...untrusted }) — spread mass assignment",
      },
      {
        regex: new RegExp(`\\.set\\s*\\(\\s*${UNTRUSTED.source}\\s*\\)`),
        label: ".set(untrusted) — update mass assignment",
      },
      {
        regex: new RegExp(`\\.set\\s*\\(\\s*\\{\\s*\\.\\.\\.${UNTRUSTED.source}\\b`),
        label: ".set({ ...untrusted }) — spread update mass assignment",
      },
    ];

    for (let i = 0; i < lines.length; i++) {
      for (const { regex, label } of PATTERNS) {
        if (regex.test(lines[i])) {
          const start = Math.max(0, i - 2);
          const end = Math.min(lines.length, i + 3);
          matches.push({
            vulnSlug: "drizzle-mass-assignment",
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

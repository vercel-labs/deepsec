import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Zod schemas declared with `.passthrough()` accept arbitrary extra fields
 * beyond what's declared. If that schema's parsed output is then used to
 * populate a DB write (Drizzle insert/update), every extra field flows
 * through unfiltered — classic mass-assignment hole.
 *
 * Flags files where:
 *   - A Zod schema uses `.passthrough()` AND
 *   - The same file performs a DB insert/update (Drizzle context)
 *
 * Even without the Drizzle pairing, `.passthrough()` on input schemas is
 * worth investigating since it widens the trust boundary of validation.
 */
export const zodPassthroughMassAssignmentMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "zod-passthrough-mass-assignment",
  description:
    "Zod schema with .passthrough() — verify parsed output isn't passed to DB write unfiltered",
  filePatterns: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.mjs"],
  examples: [
    `import { z } from "zod";\nconst schema = z.object({ name: z.string() }).passthrough();`,
    `import { z } from "zod";\nconst input = z.object({ id: z.string() }).passthrough();\nconst parsed = input.parse(req.body);\nawait db.insert(users).values(parsed);`,
    `import { z } from "zod";\nconst schema = z.object({}).passthrough();\nawait db.update(users).set(parsed);`,
    `import { z } from "zod";\nexport const userInput = z.object({ name: z.string() }).strict().passthrough();`,
    `import { z } from "zod";\nconst s = z\n  .object({ name: z.string() })\n  .passthrough();`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)$/.test(filePath)) return [];
    if (/\.d\.ts$/.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    const HAS_ZOD = /\bfrom\s+["']zod[^"']*["']|\bz\.\s*object\s*\(/;
    if (!HAS_ZOD.test(content)) return [];

    if (!/\.\s*passthrough\s*\(/.test(content)) return [];

    const lines = content.split("\n");
    const matches: CandidateMatch[] = [];

    // Higher-severity cue: same file performs a Drizzle insert/update
    const HAS_DB_WRITE =
      /\.\s*insert\s*\([^)]+\)\.\s*values\s*\(|\.\s*update\s*\([^)]+\)\.\s*set\s*\(/;
    const writeContext = HAS_DB_WRITE.test(content);

    for (let i = 0; i < lines.length; i++) {
      if (/\.\s*passthrough\s*\(/.test(lines[i])) {
        const start = Math.max(0, i - 2);
        const end = Math.min(lines.length, i + 4);
        matches.push({
          vulnSlug: "zod-passthrough-mass-assignment",
          lineNumbers: [i + 1],
          snippet: lines.slice(start, end).join("\n"),
          matchedPattern: writeContext
            ? ".passthrough() in file with DB insert/update — mass-assignment risk"
            : ".passthrough() — verify parsed output trust boundary",
        });
      }
    }
    return matches;
  },
};

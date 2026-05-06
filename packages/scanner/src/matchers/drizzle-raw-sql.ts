import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Drizzle ORM parameterizes column values when you use `eq`, `and`, `.values()`
 * etc. Its escape hatch is the `sql` template tag — `` sql`...${x}...` ``
 * — which DOES parameterize (auto-bind) interpolated expressions, BUT only
 * if you stay inside the helper. Common foot-gun: building a string outside
 * `sql\`` and then injecting it via `sql.raw(str)` or `sql.unsafe(str)`,
 * which bypasses parameterization entirely.
 *
 * Flags:
 *   - `sql.raw(...)` / `sql.unsafe(...)` calls
 *   - `` sql`...${...}...` `` where the interpolated expression is concatenation
 *     or an outside-built string variable (heuristic: `+`, template-in-template)
 *   - File must reference Drizzle (imports `drizzle-orm`, `@repo/db`, or a sibling
 *     drizzle-using module) so we don't false-positive on unrelated `sql\``
 */
export const drizzleRawSqlMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "drizzle-raw-sql",
  description: "Drizzle `sql.raw()` / `sql.unsafe()` or risky interpolation — SQL injection bypass",
  filePatterns: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.mjs"],
  requires: { tech: ["drizzle"] },
  examples: [
    `import { sql } from "drizzle-orm";\nawait db.execute(sql.raw(userQuery));`,
    `import { sql } from "drizzle-orm";\nawait db.execute(sql.unsafe(userQuery));`,
    `import { eq } from "drizzle-orm";\nawait db.execute(sql\`SELECT * FROM users WHERE name = \${"a" + b}\`);`,
    `import { sql } from "drizzle-orm";\nconst orderBy = "name";\nawait db.execute(sql\`SELECT * FROM users ORDER BY \${\`\${orderBy}\`}\`);`,
    `import { db } from "@repo/db";\ndb.execute(sql.raw("SELECT * FROM " + tableName));`,
    `import { drizzle } from "drizzle-orm/node-postgres";\nawait conn.execute(sql.unsafe(\`DROP TABLE \${name}\`));`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)$/.test(filePath)) return [];
    if (/\.d\.ts$/.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    // Drizzle context: importing drizzle-orm or @repo/db
    const HAS_DRIZZLE =
      /\bfrom\s+["'](?:drizzle-orm[^"']*|@repo\/db[^"']*|drizzle-zod|drizzle-kit)["']/;
    if (!HAS_DRIZZLE.test(content)) return [];

    const lines = content.split("\n");
    const matches: CandidateMatch[] = [];
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      let label: string | undefined;

      if (/\bsql\.\s*raw\s*\(/.test(line)) {
        label = "sql.raw() — bypasses parameterization";
      } else if (/\bsql\.\s*unsafe\s*\(/.test(line)) {
        label = "sql.unsafe() — bypasses parameterization";
      } else if (
        /\bsql`[^`]*\$\{[^}]*\+[^}]*\}/.test(line) ||
        /\bsql`[^`]*\$\{`[^`]*\$\{/.test(line)
      ) {
        // Concatenation inside sql`` — likely user-built string injected verbatim
        label = "sql`` interpolates concatenated string — verify parameter binding";
      }

      if (!label) continue;
      const start = Math.max(0, i - 1);
      const end = Math.min(lines.length, i + 3);
      matches.push({
        vulnSlug: "drizzle-raw-sql",
        lineNumbers: [i + 1],
        snippet: lines.slice(start, end).join("\n"),
        matchedPattern: label,
      });
    }
    return matches;
  },
};

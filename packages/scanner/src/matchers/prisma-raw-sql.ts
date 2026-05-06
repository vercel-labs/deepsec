import type { MatcherPlugin } from "@deepsec/core";
import { regexMatcher } from "./utils.js";

/**
 * Prisma raw-SQL escape hatches. The tagged-template variants
 * (`$queryRaw`, `$executeRaw`) are safe when called as tagged templates —
 * Prisma parameterizes the interpolations. The `*Unsafe` variants accept a
 * plain string and are SQL-injection candidates whenever the string is
 * built from anything user-controlled.
 *
 * `$queryRaw` / `$executeRaw` are also flagged because they can be misused
 * by passing a regular string instead of a tagged template (a common
 * transcription error that silently disables Prisma's parameterization).
 */
export const prismaRawSqlMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "prisma-raw-sql",
  description:
    "Prisma raw SQL ($queryRaw / $executeRaw / *Unsafe) — verify parameterization and source of inputs",
  filePatterns: ["**/*.{ts,tsx,js,jsx,mjs,cjs}"],
  requires: { tech: ["prisma"] },
  examples: [
    `await prisma.$queryRawUnsafe(\`SELECT * FROM users WHERE name = '\${name}'\`);`,
    `await prisma.$executeRawUnsafe("DELETE FROM users WHERE id = " + id);`,
    `await prisma.$queryRaw(query);`,
    `await prisma.$executeRaw(query);`,
    `await prisma.$queryRaw\`SELECT * FROM users WHERE name = \${name}\`;`,
    `await prisma.$executeRaw\`UPDATE users SET name = \${name}\`;`,
    `await prisma.$queryRaw(Prisma.raw(\`SELECT * FROM \${tableName}\`));`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)$/.test(filePath)) return [];
    if (/\.d\.ts$/.test(filePath)) return [];

    return regexMatcher(
      "prisma-raw-sql",
      [
        {
          regex: /\$queryRawUnsafe\s*\(/,
          label: "$queryRawUnsafe — string-built SQL, no parameterization",
        },
        {
          regex: /\$executeRawUnsafe\s*\(/,
          label: "$executeRawUnsafe — string-built SQL, no parameterization",
        },
        // Tagged-template form is safe; non-template invocation is not.
        // Heuristic: flag $queryRaw/$executeRaw followed by `(` instead of a backtick.
        {
          regex: /\$queryRaw\s*\(/,
          label: "$queryRaw called as function (not tagged template) — verify parameterization",
        },
        {
          regex: /\$executeRaw\s*\(/,
          label: "$executeRaw called as function (not tagged template) — verify parameterization",
        },
        // Tagged-template form: still worth a look because the interpolated values
        // could still be unsafe if mixed with Prisma.sql/raw constructions.
        {
          regex: /\$queryRaw\s*`[^`]*\$\{/,
          label: "$queryRaw template with interpolation — verify Prisma.raw isn't mixed in",
        },
        {
          regex: /\$executeRaw\s*`[^`]*\$\{/,
          label: "$executeRaw template with interpolation — verify Prisma.raw isn't mixed in",
        },
        {
          regex: /Prisma\.raw\s*\(/,
          label: "Prisma.raw — bypasses parameterization, must not include user input",
        },
      ],
      content,
    );
  },
};

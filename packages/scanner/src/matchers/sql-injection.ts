import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const sqlInjectionMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "sql-injection",
  description: "Raw SQL string concatenation or interpolation",
  filePatterns: ["**/*.{ts,tsx,js,jsx}"],
  examples: [
    "const q = `SELECT * FROM users WHERE id = ${id}`;",
    "const q = `INSERT INTO logs (msg) VALUES (${msg})`;",
    "const q = `UPDATE users SET name = ${name} WHERE id = 1`;",
    "const q = `DELETE FROM items WHERE id = ${id}`;",
    `const q = "SELECT * FROM t WHERE id =" + id;`,
    `const q = "INSERT INTO t VALUES (" + v + ")";`,
    `const q = "UPDATE t SET x = " + v;`,
    `const q = "DELETE FROM t WHERE id =" + id;`,
    "db.query(`SELECT ${col} FROM t`);",
    "knex.raw(`SELECT ${col} FROM t`);",
    "const c = `SELECT * FROM t WHERE name LIKE ${pat}`;",
    "const c = `SELECT * FROM t WHERE name LIKE '%${pat}%'`;",
    "const c = `SELECT * FROM t WHERE name RLIKE ${pat}`;",
    "executeQuery(`SELECT * FROM t WHERE id = ${id}`);",
    `sql.raw(rawString)`,
    "const r = sql`SELECT * FROM t WHERE id = ${id}`;",
  ],
  match(content, _filePath) {
    return regexMatcher(
      "sql-injection",
      [
        {
          regex: /`\s*SELECT\s+[^`]{0,400}\$\{/,
          label: "template literal SELECT with interpolation",
        },
        {
          regex: /`\s*INSERT\s+[^`]{0,400}\$\{/,
          label: "template literal INSERT with interpolation",
        },
        {
          regex: /`\s*UPDATE\s+[^`]{0,400}\$\{/,
          label: "template literal UPDATE with interpolation",
        },
        {
          regex: /`\s*DELETE\s+[^`]{0,400}\$\{/,
          label: "template literal DELETE with interpolation",
        },
        { regex: /['"]SELECT\s+[^'"]{0,400}['"]\s*\+/, label: "string concat SELECT" },
        { regex: /['"]INSERT\s+[^'"]{0,400}['"]\s*\+/, label: "string concat INSERT" },
        { regex: /['"]UPDATE\s+[^'"]{0,400}['"]\s*\+/, label: "string concat UPDATE" },
        { regex: /['"]DELETE\s+[^'"]{0,400}['"]\s*\+/, label: "string concat DELETE" },
        { regex: /query\s*\(\s*`[^`]*\$\{/, label: "query() with interpolation" },
        { regex: /\.raw\s*\(\s*`[^`]*\$\{/, label: ".raw() with interpolation" },
        { regex: /LIKE\s+['"]?%?\$\{/, label: "LIKE with interpolation" },
        { regex: /LIKE\s+['"]%\$\{/, label: "LIKE '%${...}%' pattern" },
        { regex: /RLIKE\s+['"]?\$\{/, label: "RLIKE with interpolation" },
        {
          regex: /executeQuery\w*\s*\(\s*`[^`]*\$\{/,
          label: "executeQuery with template interpolation",
        },
        { regex: /sql\.raw\s*\(/, label: "sql.raw() — raw SQL (verify parameterized)" },
        {
          regex: /sql`[^`]{0,400}\$\{[^}]{0,200}\}/,
          label: "sql tagged template with interpolation",
        },
      ],
      content,
    );
  },
};

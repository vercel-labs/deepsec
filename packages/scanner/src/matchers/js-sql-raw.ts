import type { MatcherPlugin } from "@deepsec/core";
import { regexMatcher } from "./utils.js";

/**
 * Raw-SQL escape hatches across the popular JS/TS database drivers and
 * query builders. The common failure mode is the same in every flavor:
 * the SQL string is built via template-literal interpolation or `+`
 * concatenation with values that came from request input. Parameterized
 * queries (`$1`, `?`, named bindings) are safe; the patterns below flag
 * the unsafe shapes.
 *
 * Drivers / libraries covered:
 *   - node-postgres (`pg`)
 *   - mysql2 / mysql
 *   - TypeORM (`repository.query`, `@Query`)
 *   - Sequelize (`sequelize.query`, `Sequelize.literal`, `Sequelize.fn`)
 *   - Knex (`raw`, `whereRaw`, `orderByRaw`, `havingRaw`)
 *   - Kysely (`sql.raw`, `sql.lit`)
 *   - postgres.js / porsager (`sql.unsafe`)
 *   - better-sqlite3 (`db.prepare`, `db.exec`)
 *   - generic `query("...")` shapes for drivers we don't enumerate
 */
export const jsSqlRawMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "js-sql-raw",
  description:
    "Raw SQL escape hatches across popular JS/TS DB drivers (pg, mysql2, TypeORM, Sequelize, Knex, Kysely, postgres.js, better-sqlite3) — interpolated input is SQL injection",
  filePatterns: ["**/*.{ts,tsx,js,jsx,mjs,cjs}"],
  examples: [
    `client.query("SELECT * FROM users WHERE id = " + userId)`,
    `pool.query(\`SELECT * FROM users WHERE id = \${id}\`)`,
    `await conn.query("DELETE FROM x WHERE y = '" + name + "'")`,
    `repo.query(\`UPDATE users SET role = '\${role}' WHERE id = \${id}\`)`,
    `sequelize.query(\`SELECT * FROM t WHERE col = '\${input}'\`)`,
    `Sequelize.literal(\`COUNT(*) FILTER (WHERE x = \${x})\`)`,
    `knex.raw(\`SELECT * FROM users WHERE id = \${id}\`)`,
    `qb.whereRaw("col = '" + value + "'")`,
    `db.selectFrom("users").where(sql.raw("col = " + x))`,
    `sql.unsafe(\`SELECT * FROM x WHERE y = \${y}\`)`,
    `db.prepare(\`SELECT * FROM users WHERE name = '\${name}'\`)`,
    `@Query(\`SELECT * FROM x WHERE y = '\${z}'\` + suffix)`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)$/.test(filePath)) return [];
    if (/\.d\.ts$/.test(filePath)) return [];

    return regexMatcher(
      "js-sql-raw",
      [
        // node-postgres / pg-pool / generic `client|pool|conn.query("SELECT ...${x}")`
        {
          regex:
            /\b(?:client|pool|conn)\.query\s*\(\s*['"`]\s*(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP)\b[^)]{0,400}\$\{/i,
          label:
            "node-postgres/pg: client/pool/conn.query with template-literal interpolation — SQL injection",
        },
        // Generic .query("...") + something — concatenation onto a SQL literal
        {
          regex: /\.query\s*\(\s*['"`][^'"`]{0,200}['"`]\s*\+/,
          label: ".query('...') with string concatenation — SQL injection",
        },
        // mysql2 / mysql informational signal — flags use of the library so a
        // reviewer spots the import alongside any unsafe pattern matches above.
        {
          regex: /\bmysql\.createConnection\s*\(|require\(\s*['"]mysql2?['"]\s*\)/,
          label:
            "mysql/mysql2 driver in use — verify all query() calls use placeholders, not concatenation",
        },
        // TypeORM raw query API
        {
          regex:
            /\b(?:repo|repository|entityManager|manager|connection|dataSource|getRepository\(\w+\))\.query\s*\(/,
          label:
            "TypeORM repository/manager.query — raw SQL, must use parameter array not interpolation",
        },
        // TypeORM @Query decorator with string concat
        {
          regex: /@Query\s*\(\s*['"`][^'"`]{0,400}['"`]\s*\+/,
          label: "TypeORM @Query with string concatenation — SQL injection",
        },
        // Sequelize: sequelize.query with template interpolation
        {
          regex: /\bsequelize\.query\s*\(\s*`?[^`)]{0,400}\$\{/,
          label:
            "Sequelize sequelize.query with template-literal interpolation — pass replacements/bind instead",
        },
        // Sequelize.literal — bypasses parameterization
        {
          regex: /Sequelize\.literal\s*\(/,
          label: "Sequelize.literal — bypasses escaping; must not include user input",
        },
        // Sequelize.fn with interpolated argument
        {
          regex: /Sequelize\.fn\s*\(\s*['"`][A-Z]+['"`]\s*,\s*\$\{/,
          label: "Sequelize.fn with template-literal interpolation — SQL injection",
        },
        // Knex .raw with interpolation
        {
          regex: /\.raw\s*\(\s*['"`][^'"`]{0,400}\$\{/,
          label: "Knex .raw with template-literal interpolation — SQL injection",
        },
        // Knex .whereRaw / .orderByRaw / .havingRaw — any use is worth a look
        {
          regex: /\.whereRaw\s*\(/,
          label: "Knex .whereRaw — verify bindings are passed as second argument, not interpolated",
        },
        {
          regex: /\.orderByRaw\s*\(/,
          label:
            "Knex .orderByRaw — verify bindings are passed as second argument, not interpolated",
        },
        {
          regex: /\.havingRaw\s*\(/,
          label:
            "Knex .havingRaw — verify bindings are passed as second argument, not interpolated",
        },
        // Kysely sql.raw / sql.lit
        {
          regex: /\bsql\.raw\s*\(/,
          label: "Kysely sql.raw — bypasses parameterization, must not include user input",
        },
        {
          regex: /\bsql\.lit\s*\(/,
          label: "Kysely sql.lit — inserts literal SQL, must not include user input",
        },
        // postgres.js (porsager) sql.unsafe
        {
          regex: /\bsql\.unsafe\s*\(/,
          label: "postgres.js sql.unsafe — bypasses parameterization, must not include user input",
        },
        // better-sqlite3: db.prepare(`...${x}...`)
        {
          regex: /\bdb\.prepare\s*\(\s*`[^`]{0,400}\$\{/,
          label:
            "better-sqlite3 db.prepare with template-literal interpolation — use bound parameters",
        },
        // better-sqlite3: db.exec(`...${x}...`)
        {
          regex: /\bdb\.exec\s*\(\s*`[^`]{0,400}\$\{/,
          label:
            "better-sqlite3 db.exec with template-literal interpolation — db.exec cannot bind, refactor to prepare()",
        },
        // Generic catch-all: query("SELECT ...") + ... for drivers we don't name
        {
          regex: /\bquery\s*\(\s*['"`]\s*(?:SELECT|INSERT|UPDATE|DELETE)\b[^)]{0,400}['"`]\s*\+/i,
          label: "Generic .query('SELECT/INSERT/...') with string concatenation — SQL injection",
        },
      ],
      content,
    );
  },
};

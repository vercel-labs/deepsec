import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const goSqlRawMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "go-sql-raw",
  description:
    "Raw SQL across Go DB libraries (database/sql, GORM, sqlx, pgx) — fmt.Sprintf or + concatenation into queries is SQL injection",
  filePatterns: ["**/*.go"],
  requires: { tech: ["go"] },
  examples: [
    `rows, err := db.Query("SELECT * FROM users WHERE id = " + userId)`,
    `db.QueryRow(fmt.Sprintf("SELECT * FROM x WHERE y = '%s'", name))`,
    `db.Exec("DELETE FROM users WHERE id = " + id)`,
    `db.Raw("SELECT * FROM users WHERE id = " + id).Scan(&user)`,
    `db.Raw(fmt.Sprintf("UPDATE users SET role = '%s'", role)).Exec()`,
    `db.Where("name = '" + name + "'").First(&user)`,
    `db.Where(fmt.Sprintf("id = %d", id)).First(&u)`,
    `err := sqlxDb.Select(&users, "SELECT * FROM users WHERE name = '" + name + "'")`,
    `row := pool.QueryRow(ctx, "SELECT id FROM users WHERE email = '" + email + "'")`,
    `conn.QueryRowContext(ctx, fmt.Sprintf("SELECT * FROM t WHERE id = %d", id))`,
  ],
  match(content, filePath) {
    if (/_test\.go$/.test(filePath)) return [];

    return regexMatcher(
      "go-sql-raw",
      [
        // database/sql
        {
          regex:
            /\bdb\.(?:Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext)\s*\(\s*"[^"]{0,400}"\s*\+/,
          label: "database/sql Query/Exec with string concat",
        },
        {
          regex: /\bdb\.(?:Query|QueryRow|Exec)\s*\(\s*fmt\.Sprintf\s*\(/,
          label: "database/sql Query/Exec with fmt.Sprintf",
        },
        // GORM
        {
          regex: /\bdb\.Raw\s*\(\s*fmt\.Sprintf\s*\(/,
          label: "GORM db.Raw with fmt.Sprintf",
        },
        {
          regex: /\bdb\.Raw\s*\(\s*"[^"]{0,400}"\s*\+/,
          label: "GORM db.Raw with string concat",
        },
        {
          regex: /\bdb\.Exec\s*\(\s*fmt\.Sprintf\s*\(/,
          label: "GORM db.Exec with fmt.Sprintf",
        },
        {
          regex: /\bdb\.Where\s*\(\s*fmt\.Sprintf\s*\(/,
          label: "GORM db.Where with fmt.Sprintf",
        },
        {
          regex: /\bdb\.Where\s*\(\s*"[^"]{0,400}=\s*'?\s*"\s*\+/,
          label: "GORM db.Where with string concat",
        },
        // sqlx
        {
          regex:
            /\bdb\.(?:Select|Get|QueryxContext|NamedQuery)\s*\(\s*&?\w*,?\s*"[^"]{0,400}"\s*\+/,
          label: "sqlx Select/Get/Queryx with string concat",
        },
        {
          regex: /\bsqlx\.MustExec\s*\(\s*\w+\s*,\s*fmt\.Sprintf/,
          label: "sqlx.MustExec with fmt.Sprintf",
        },
        // pgx
        {
          regex: /\b(?:conn|pool)\.Query(?:Row)?(?:Context)?\s*\(\s*\w*,?\s*"[^"]{0,400}"\s*\+/,
          label: "pgx conn/pool.Query with string concat",
        },
        {
          regex: /\b(?:conn|pool)\.Query(?:Row)?(?:Context)?\s*\(\s*\w*,?\s*fmt\.Sprintf/,
          label: "pgx conn/pool.Query with fmt.Sprintf",
        },
        {
          regex: /\bpgx\.Connect\s*\(/,
          label: "pgx.Connect (informational signal)",
        },
        // Generic Go SQL
        {
          regex: /"\s*(?:SELECT|INSERT|UPDATE|DELETE)[^"]{0,400}"\s*\+\s*\w/,
          label: "SQL keyword string literal followed by concat",
        },
      ],
      content,
    );
  },
};

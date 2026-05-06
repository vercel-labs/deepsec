import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const rsSqlRawMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "rs-sql-raw",
  description:
    "Raw SQL escape hatches in Rust DB crates (sqlx::query with format!, diesel sql_query, sea-orm Statement::from_string) — note that sqlx::query!() macro is compile-time-checked and SAFE",
  filePatterns: ["**/*.rs"],
  requires: { tech: ["rust"] },
  // SAFE counterpart (NOT in `examples` since the discovery test only
  // accepts positive cases): the compile-time-checked macro form
  // `sqlx::query!("SELECT * FROM users WHERE id = $1", id)` is parameterized
  // at compile time and is NOT a finding. Only the runtime
  // `sqlx::query(&format!(...))` form below is unsafe.
  examples: [
    `sqlx::query(&format!("SELECT * FROM users WHERE id = {}", id)).fetch_one(&pool).await?`,
    `sqlx::query_as::<_, User>(&format!("SELECT * FROM users WHERE name = '{}'", name)).fetch_all(&pool).await?`,
    `sqlx::query(&format!("DELETE FROM users WHERE id = {}", id)).execute(&pool).await?`,
    `diesel::sql_query(format!("SELECT * FROM users WHERE id = {}", id)).load(conn)?`,
    `Statement::from_string(DbBackend::Postgres, format!("SELECT * FROM x WHERE y = '{}'", y))`,
    `conn.execute(&format!("DELETE FROM users WHERE id = {}", id), [])?`,
  ],
  match(content, filePath) {
    if (/\/(tests|examples)\//.test(filePath)) return [];

    return regexMatcher(
      "rs-sql-raw",
      [
        // sqlx (NON-macro, runtime form)
        {
          regex: /\bsqlx::query\s*\(\s*&?format!\s*\(/,
          label: "sqlx::query(&format!(...)) — runtime, unsafe",
        },
        {
          regex: /\bsqlx::query_as\s*::<[^>]+>\s*\(\s*&?format!\s*\(/,
          label: "sqlx::query_as::<...>(&format!(...)) — runtime, unsafe",
        },
        {
          regex: /\bsqlx::query\s*\(\s*&?String::from\s*\(\s*format!/,
          label: "sqlx::query(String::from(format!(...))) — runtime, unsafe",
        },
        // diesel
        {
          regex: /\bsql_query\s*\(\s*format!\s*\(/,
          label: "diesel::sql_query(format!(...))",
        },
        {
          regex: /\bsql_query\s*\(\s*&?String::from\s*\(\s*format!/,
          label: "diesel::sql_query(String::from(format!(...)))",
        },
        // sea-orm
        {
          regex: /\bStatement::from_string\s*\(/,
          label: "sea-orm Statement::from_string",
        },
        {
          regex: /\bStatement::from_sql_and_values\s*\(\s*\w+,\s*format!\s*\(/,
          label: "sea-orm Statement::from_sql_and_values with format!",
        },
        // rusqlite
        {
          regex: /\bconn\.execute\s*\(\s*&?format!\s*\(/,
          label: "rusqlite conn.execute(&format!(...))",
        },
        {
          regex: /\bconn\.prepare\s*\(\s*&?format!\s*\(/,
          label: "rusqlite conn.prepare(&format!(...))",
        },
        // Generic format! into SQL keywords
        {
          regex: /format!\s*\(\s*"\s*(?:SELECT|INSERT|UPDATE|DELETE)/,
          label: "format!() with SQL keyword as first arg",
        },
      ],
      content,
    );
  },
};

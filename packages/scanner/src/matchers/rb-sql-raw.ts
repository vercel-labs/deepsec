import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

/**
 * Raw SQL across Ruby DB libraries (ActiveRecord raw, Sequel.lit, pg gem).
 * String interpolation (`#{...}`) into SQL strings is SQL injection.
 */
export const rbSqlRawMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "rb-sql-raw",
  description:
    "Raw SQL across Ruby DB libraries (ActiveRecord raw, Sequel.lit, pg gem) — string interpolation is SQL injection",
  filePatterns: ["**/*.rb"],
  requires: { tech: ["ruby"] },
  examples: [
    `User.find_by_sql("SELECT * FROM users WHERE name = '#{name}'")`,
    `User.where("name = '#{name}'")`,
    `User.where("id = #{user_id}")`,
    `User.connection.execute("DELETE FROM users WHERE id = #{id}")`,
    `ActiveRecord::Base.connection.execute("UPDATE users SET role = '#{role}'")`,
    `DB[:users].where("name = '#{q}'")`,
    `DB.fetch("SELECT * FROM t WHERE col = '#{val}'")`,
    `Sequel.lit("name = '#{user_input}'")`,
    `conn.exec("SELECT * FROM users WHERE id = #{user_id}")`,
  ],
  match(content, filePath) {
    if (/\/(test|spec)\//.test(filePath)) return [];

    return regexMatcher(
      "rb-sql-raw",
      [
        // ActiveRecord raw
        {
          regex: /\bfind_by_sql\s*\(\s*"[^"]{0,400}#\{/m,
          label: "find_by_sql with #{} interpolation (SQL injection)",
        },
        {
          regex: /\.where\s*\(\s*"[^"]{0,400}#\{/m,
          label: ".where with #{} interpolation (SQL injection)",
        },
        {
          regex: /\.find_by_sql\s*\(\s*\[\s*"[^"]{0,400}#\{/m,
          label: "find_by_sql array form with #{} (SQL injection)",
        },
        {
          regex: /\.connection\.execute\s*\(\s*"[^"]{0,400}#\{/m,
          label: "connection.execute with #{} interpolation (SQL injection)",
        },
        {
          regex: /\bActiveRecord::Base\.connection\.execute\s*\(/,
          label: "ActiveRecord::Base.connection.execute (raw SQL surface)",
        },
        // Sequel
        {
          regex: /\bSequel\.lit\s*\(\s*"[^"]{0,400}#\{/m,
          label: "Sequel.lit with #{} interpolation (SQL injection)",
        },
        {
          regex: /\bDB\.fetch\s*\(\s*"[^"]{0,400}#\{/m,
          label: "Sequel DB.fetch with #{} interpolation (SQL injection)",
        },
        {
          regex: /\bDB\[:\w+\]\.where\s*\(\s*"[^"]{0,400}#\{/m,
          label: "Sequel DB[:t].where with #{} interpolation (SQL injection)",
        },
        // pg gem direct
        {
          regex: /\bconn\.exec\s*\(\s*"[^"]{0,400}#\{/m,
          label: "pg gem conn.exec with #{} interpolation (SQL injection)",
        },
        {
          regex: /\bPG::Connection\.new/,
          label: "PG::Connection.new (informational signal)",
        },
        // Generic Ruby SQL with interpolation
        {
          regex: /"\s*(?:SELECT|INSERT|UPDATE|DELETE)[^"]{0,400}#\{/m,
          label: "Raw SQL string with #{} interpolation (SQL injection)",
        },
      ],
      content,
    );
  },
};

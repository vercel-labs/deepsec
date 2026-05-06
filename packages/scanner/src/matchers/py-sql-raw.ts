import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

/**
 * Raw SQL escape hatches across popular Python DB drivers.
 *
 * Covers SQLAlchemy (engine.execute / session.execute / text()),
 * psycopg / psycopg2 / pymysql / sqlite3 / asyncpg (cursor.execute and
 * the asyncpg connection methods), and the Django ORM raw escape
 * hatches (Model.objects.raw / .extra / connection.cursor().execute).
 *
 * The danger signal is string interpolation feeding the SQL: f-strings,
 * `%`-formatting, `.format()`, and `+` concatenation all bypass the
 * driver's parameterization and hand the user's input directly to the
 * SQL engine.
 */
export const pySqlRawMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "py-sql-raw",
  description:
    "Raw SQL across popular Python DB drivers (SQLAlchemy, psycopg, pymysql, sqlite3, asyncpg, Django ORM raw) — f-string / %-format / .format / + interpolation is SQL injection",
  filePatterns: ["**/*.py"],
  requires: { tech: ["python"] },
  examples: [
    `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`,
    `cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)`,
    `cursor.execute("DELETE FROM x WHERE y = '" + name + "'")`,
    `cursor.execute("SELECT * FROM t WHERE col = '{}'".format(val))`,
    `engine.execute(text(f"SELECT * FROM users WHERE name = '{name}'"))`,
    `session.execute(f"UPDATE users SET role = '{role}'")`,
    `text(f"SELECT id FROM users WHERE email = '{email}'")`,
    `User.objects.raw(f"SELECT * FROM users WHERE name = '{name}'")`,
    `User.objects.extra(where=[f"name = '{name}'"])`,
    `await conn.execute(f"DELETE FROM users WHERE id = {user_id}")`,
  ],
  match(content, filePath) {
    if (/\b(?:tests?|migrations)\b/i.test(filePath)) return [];

    return regexMatcher(
      "py-sql-raw",
      [
        // SQLAlchemy
        {
          regex: /\bengine\.execute\s*\(\s*(?:text\s*\(\s*)?f['"]/,
          label: "SQLAlchemy engine.execute with f-string — SQL injection",
        },
        {
          regex: /\bsession\.execute\s*\(\s*(?:text\s*\(\s*)?f['"]/,
          label: "SQLAlchemy session.execute with f-string — SQL injection",
        },
        {
          regex: /\btext\s*\(\s*f['"]/,
          label: "SQLAlchemy text() with f-string — bypasses parameterization",
        },
        {
          regex: /\bsession\.execute\s*\(\s*(?:"[^"]{0,400}"|'[^']{0,400}')\s*%/,
          label: "SQLAlchemy session.execute with %-formatting — SQL injection",
        },
        // psycopg / psycopg2 / pymysql / sqlite3 / asyncpg
        {
          regex: /\bcursor\.execute\s*\(\s*f['"]/,
          label: "cursor.execute with f-string — SQL injection",
        },
        {
          regex: /\bcursor\.execute\s*\(\s*(?:"[^"]{0,400}"|'[^']{0,400}')\s*%/,
          label: "cursor.execute with %-formatting — SQL injection",
        },
        {
          regex: /\bcursor\.execute\s*\(\s*(?:"[^"]{0,400}"|'[^']{0,400}')\s*\.format\s*\(/,
          label: "cursor.execute with .format() — SQL injection",
        },
        {
          regex: /\bcursor\.execute\s*\(\s*(?:"[^"]{0,400}"|'[^']{0,400}')\s*\+/,
          label: "cursor.execute with string concatenation — SQL injection",
        },
        {
          regex: /\bawait\s+conn\.(?:execute|fetch|fetchrow|fetchval)\s*\(\s*f['"]/,
          label: "asyncpg conn.execute/fetch* with f-string — SQL injection",
        },
        // Django ORM raw escape hatches
        {
          regex: /\b\w+\.objects\.raw\s*\(\s*f['"]/,
          label: "Django Model.objects.raw with f-string — SQL injection",
        },
        {
          regex: /\b\w+\.objects\.raw\s*\(\s*(?:"[^"]{0,400}"|'[^']{0,400}')\s*%/,
          label: "Django Model.objects.raw with %-formatting — SQL injection",
        },
        {
          regex: /\b\w+\.objects\.extra\s*\(\s*where\s*=\s*\[\s*f?['"]/,
          label: "Django Model.objects.extra(where=...) — string-built WHERE clause",
        },
        {
          regex: /\bconnection\.cursor\(\)\.execute\s*\(\s*f['"]/,
          label: "Django connection.cursor().execute with f-string — SQL injection",
        },
        // Generic
        {
          regex: /\bdb\.execute\s*\(\s*f['"]\s*(?:SELECT|INSERT|UPDATE|DELETE)/,
          label: "db.execute with f-string SQL — SQL injection",
        },
      ],
      content,
    );
  },
};

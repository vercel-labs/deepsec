import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const jvmSqlRawMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "jvm-sql-raw",
  description:
    "Raw SQL across JVM DB libraries (JDBC, JPA/Hibernate, Spring JdbcTemplate, MyBatis, jOOQ, Exposed) — string concatenation or interpolation is SQL injection",
  filePatterns: ["**/*.{java,kt}"],
  requires: { tech: ["jvm"] },
  examples: [
    `stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);`,
    `stmt.executeQuery("SELECT * FROM x WHERE y = '" + name + "'")`,
    `stmt.executeUpdate("DELETE FROM users WHERE id = " + id)`,
    `Connection conn = DriverManager.getConnection(url);`,
    `connection.prepareStatement("SELECT * FROM users WHERE name = '" + name + "'")`,
    `em.createNativeQuery("SELECT * FROM users WHERE id = " + id)`,
    `em.createQuery("FROM User u WHERE u.name = '" + name + "'")`,
    `session.createSQLQuery("SELECT * FROM x WHERE col = '" + col + "'")`,
    `jdbcTemplate.query("SELECT * FROM users WHERE id = " + id, mapper)`,
    `jdbcTemplate.update("UPDATE users SET role = '" + role + "' WHERE id = " + id)`,
    `@Select("SELECT * FROM users WHERE id = \${id}")`,
    `val rows = exec("SELECT * FROM users WHERE name = '\${name}'")`,
    `val sql = "SELECT * FROM t WHERE col = '\${input}'"`,
    `DSL.field("a." + col)`,
  ],
  match(content, filePath) {
    if (/\/(test|tests)\//.test(filePath)) return [];

    return regexMatcher(
      "jvm-sql-raw",
      [
        // JDBC
        {
          regex: /\b(?:Statement|stmt)\.executeQuery\s*\(\s*"[^"]{0,400}"\s*\+/,
          label: 'Statement.executeQuery("..." + ...) — concat into JDBC query',
        },
        {
          regex:
            /\b(?:Statement|stmt)\.execute(?:Update|Query|LargeUpdate)?\s*\(\s*"[^"]{0,400}"\s*\+/,
          label: 'Statement.execute*("..." + ...) — concat into JDBC statement',
        },
        {
          regex: /\.createStatement\s*\(\s*\)\s*\.execute(?:Query|Update|LargeUpdate)?\s*\(/,
          label: "createStatement().execute*(...) — JDBC Statement (no parameterization)",
        },
        {
          // Match both `Connection.prepareStatement` and any `<conn>.prepareStatement(...)`
          // shape since instance variable names vary (`conn`, `connection`, `db`, …).
          regex: /\b\w*[Cc]on(?:nection)?\.prepareStatement\s*\(\s*"[^"]{0,400}"\s*\+/,
          label: '<conn>.prepareStatement("..." + ...) — concat defeats parameterization',
        },
        {
          regex: /\bDriverManager\.getConnection\s*\(/,
          label: "DriverManager.getConnection(...) — JDBC in use (informational)",
        },

        // JPA / Hibernate
        {
          regex: /\b(?:em|entityManager|session)\.createNativeQuery\s*\(\s*"[^"]{0,400}"\s*\+/,
          label: 'createNativeQuery("..." + ...) — concat into JPA/Hibernate native SQL',
        },
        {
          regex: /\b(?:em|entityManager|session)\.createQuery\s*\(\s*"[^"]{0,400}"\s*\+/,
          label: 'createQuery("..." + ...) — concat into HQL/JPQL (still injectable)',
        },
        {
          regex: /\bsession\.createSQLQuery\s*\(\s*"[^"]{0,400}"\s*\+/,
          label: 'session.createSQLQuery("..." + ...) — concat into Hibernate SQL',
        },

        // Spring JdbcTemplate
        {
          regex:
            /\bjdbcTemplate\.(?:query|update|queryForObject|queryForList|execute|batchUpdate)\s*\(\s*"[^"]{0,400}"\s*\+/,
          label: 'jdbcTemplate.<op>("..." + ...) — concat into Spring JdbcTemplate',
        },
        {
          regex: /\bnamedParameterJdbcTemplate\.(?:query|update)\s*\(\s*"[^"]{0,400}"\s*\+/,
          label: 'namedParameterJdbcTemplate.<op>("..." + ...) — concat defeats named params',
        },

        // MyBatis
        {
          regex: /@Select\s*\(\s*"[^"]{0,400}\$\{/,
          label: '@Select("...${...}") — MyBatis ${param} is unsafe (use #{param})',
        },
        {
          regex: /\bselectList\s*\(\s*"[^"]{0,400}"\s*\+|\bselectOne\s*\(\s*"[^"]{0,400}"\s*\+/,
          label: 'selectList/selectOne("..." + ...) — concat into MyBatis statement id',
        },

        // jOOQ
        {
          regex: /\bDSL\.field\s*\(\s*"[^"]{0,400}"\s*\+/,
          label: 'DSL.field("..." + ...) — jOOQ raw field with concat',
        },
        {
          regex: /\bdsl\.execute\s*\(\s*"[^"]{0,400}"\s*\+/,
          label: 'dsl.execute("..." + ...) — concat into jOOQ raw execute',
        },
        {
          regex: /\bDSL\.sql\s*\(/,
          label: "DSL.sql(...) — jOOQ raw SQL escape hatch",
        },

        // Exposed (Kotlin)
        {
          regex: /\bexec\s*\(\s*"[^"]{0,400}\$\{/,
          label: 'exec("...${...}") — Exposed exec with Kotlin template interpolation',
        },
        {
          regex: /\bTransactionManager\.current\(\)\.exec\s*\(/,
          label: "TransactionManager.current().exec(...) — Exposed raw exec",
        },

        // Kotlin string templates with SQL keywords
        {
          regex: /"\s*(?:SELECT|INSERT|UPDATE|DELETE)[^"]{0,400}\$\{/,
          label: '"SELECT/INSERT/UPDATE/DELETE ...${...}" — Kotlin string template into raw SQL',
        },
      ],
      content,
    );
  },
};

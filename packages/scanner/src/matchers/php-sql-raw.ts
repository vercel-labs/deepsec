import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

/**
 * Raw SQL across PHP DB drivers (PDO, mysqli, Doctrine ORM/DBAL). String
 * concatenation into query/exec/prepare/executeQuery/executeStatement is
 * SQL injection. Concat into prepare also defeats parameterization.
 */
export const phpSqlRawMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "php-sql-raw",
  description:
    "Raw SQL across PHP DB drivers (PDO, mysqli, Doctrine ORM/DBAL) — string concatenation is SQL injection",
  filePatterns: ["**/*.php"],
  requires: { tech: ["php"] },
  examples: [
    `<?php\n$result = $pdo->query("SELECT * FROM users WHERE id = " . $id);`,
    `$pdo->exec("DELETE FROM users WHERE name = '" . $name . "'");`,
    `$stmt = $pdo->prepare("SELECT * FROM t WHERE col = '" . $col . "'");`,
    `mysqli_query($conn, "SELECT * FROM users WHERE id = " . $userId);`,
    `$conn->executeQuery("UPDATE users SET role = '" . $role . "' WHERE id = " . $id);`,
    `$conn->executeStatement("DELETE FROM users WHERE id = " . $id);`,
    `$em->createQuery("SELECT u FROM App\\User u WHERE u.name = '" . $name . "'");`,
    `$em->createNativeQuery("SELECT * FROM users WHERE id = " . $id, $rsm);`,
    `$sql = "INSERT INTO logs (msg) VALUES ('" . $msg . "')";`,
  ],
  match(content, filePath) {
    if (/\/(tests|vendor)\//.test(filePath)) return [];

    // Quoted-string class — accepts ' and " separately so a SQL string
    // containing a literal `'` (very common in `WHERE name = '...'`) doesn't
    // close the regex's character class early.
    const QSTR = `(?:"[^"]{0,400}"|'[^']{0,400}')`;
    return regexMatcher(
      "php-sql-raw",
      [
        // PDO
        {
          regex: new RegExp(`\\$\\w+->query\\s*\\(\\s*${QSTR}\\s*\\.\\s*\\$`),
          label: "PDO->query with string concat (SQL injection)",
        },
        {
          regex: new RegExp(`\\$\\w+->exec\\s*\\(\\s*${QSTR}\\s*\\.\\s*\\$`),
          label: "PDO->exec with string concat (SQL injection)",
        },
        {
          regex: new RegExp(`\\$\\w+->prepare\\s*\\(\\s*${QSTR}\\s*\\.\\s*\\$`),
          label: "PDO->prepare with concat (defeats parameterization)",
        },
        { regex: /new\s+PDO\s*\(/, label: "PDO connection (informational)" },
        // mysqli
        {
          regex: new RegExp(`mysqli_query\\s*\\(\\s*[^,]+,\\s*${QSTR}\\s*\\.\\s*\\$`),
          label: "mysqli_query with string concat (SQL injection)",
        },
        {
          regex: /mysqli_real_escape_string/,
          label: "mysqli_real_escape_string (informational — manual escaping)",
        },
        // Doctrine DBAL
        {
          regex: new RegExp(`\\$\\w+->executeQuery\\s*\\(\\s*${QSTR}\\s*\\.\\s*\\$`),
          label: "Doctrine DBAL executeQuery with concat (SQL injection)",
        },
        {
          regex: new RegExp(`\\$\\w+->executeStatement\\s*\\(\\s*${QSTR}\\s*\\.\\s*\\$`),
          label: "Doctrine DBAL executeStatement with concat (SQL injection)",
        },
        // Doctrine ORM
        {
          regex: new RegExp(`\\$\\w+->createQuery\\s*\\(\\s*${QSTR}\\s*\\.\\s*\\$`),
          label: "Doctrine ORM createQuery (DQL) with concat (injection)",
        },
        {
          regex: new RegExp(`\\$\\w+->createNativeQuery\\s*\\(\\s*${QSTR}\\s*\\.\\s*\\$`),
          label: "Doctrine ORM createNativeQuery with concat (SQL injection)",
        },
        // Generic SQL keywords with concat — match a quoted SQL literal
        // followed by `.` `$var`. The opening quote dictates the matching
        // closing quote, so `'` inside a `"..."` string is fine.
        {
          regex: new RegExp(
            `(?:"\\s*(?:SELECT|INSERT|UPDATE|DELETE)\\s+[^"]{0,400}"|'\\s*(?:SELECT|INSERT|UPDATE|DELETE)\\s+[^']{0,400}')\\s*\\.\\s*\\$\\w+`,
          ),
          label: "Raw SQL string with concat (SQL injection)",
        },
      ],
      content,
    );
  },
};

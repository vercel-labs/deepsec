import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Analytics-tier SQL injection (Snowflake / BigQuery / DuckDB / ClickHouse).
 * These look like analytics, but the destination is a real query engine
 * and template-literal interpolation is exploitable just as on Postgres.
 *
 * Flags:
 *   - `snowflake.execute({ sqlText: \`...${...}...\` })`
 *   - `connection.execute(\`SELECT ... ${...}\`)` in snowflake-sdk context
 *   - `bigquery.query(\`...${...}\`)` / `bigquery.createQueryJob({query: \`...\`})`
 *   - `clickhouse.query(\`...${...}\`)` / `client.query({query: \`...\`})`
 */
export const snowflakeBigquerySqlMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "snowflake-bigquery-sql",
  description: "Snowflake / BigQuery / ClickHouse SQL via template/string interpolation",
  filePatterns: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.mjs"],
  examples: [
    `import snowflake from "snowflake-sdk";\nconnection.execute({ sqlText: \`SELECT * FROM users WHERE id = \${id}\` });`,
    `import snowflake from "snowflake-sdk";\nconnection.execute({ sqlText: "SELECT * FROM users WHERE id = " + id });`,
    `import { BigQuery } from "@google-cloud/bigquery";\nawait bigquery.query(\`SELECT * FROM users WHERE id = \${id}\`);`,
    `import { BigQuery } from "@google-cloud/bigquery";\nawait bigquery.createQueryJob({ query: \`SELECT * FROM \${tableName}\` });`,
    `import { createClient } from "@clickhouse/client";\nawait clickhouse.query(\`SELECT * FROM users WHERE id = \${id}\`);`,
    `import { createClient } from "@clickhouse/client";\nawait client.query({ query: \`SELECT * FROM \${table}\` });`,
    `import duckdb from "duckdb";\nawait connection.execute(\`SELECT * FROM \${table}\`);`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)$/.test(filePath)) return [];
    if (/\.d\.ts$/.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    const HAS_ANALYTICS =
      /\bfrom\s+["'](?:snowflake-sdk|@google-cloud\/bigquery|@clickhouse\/client|@clickhouse\/client-web|@databricks\/sql|duckdb|@duckdb\/[^"']*)["']/;
    if (!HAS_ANALYTICS.test(content)) return [];

    const lines = content.split("\n");
    const matches: CandidateMatch[] = [];

    // sqlText: `...${...}...`
    const SQLTEXT_TPL = /\bsqlText\s*:\s*`[^`]*\$\{/;
    // .execute({sqlText: ...}) with concat
    const SQLTEXT_CONCAT = /\bsqlText\s*:\s*["'][^"']*["']\s*\+/;
    // bigquery / clickhouse query() with template
    const QUERY_TPL =
      /\b(?:bigquery|bq|clickhouse|client|connection)\.\s*query\s*\(\s*\{?\s*(?:query\s*:\s*)?`[^`]*\$\{/;
    // bigquery createQueryJob / Snowflake execute({sqlText:...}) with template
    const CREATE_JOB_TPL = /\bcreateQueryJob\s*\(\s*\{[^}]*query\s*:\s*`[^`]*\$\{/;
    // generic .execute(`...${...}`) inside an analytics-importing file
    const EXEC_TPL = /\b(?:connection|conn|client|db)\.\s*execute\s*\(\s*`[^`]*\$\{/;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      let label: string | undefined;
      if (SQLTEXT_TPL.test(line)) label = "Snowflake sqlText with template interpolation";
      else if (SQLTEXT_CONCAT.test(line)) label = "Snowflake sqlText with string concatenation";
      else if (CREATE_JOB_TPL.test(line))
        label = "BigQuery createQueryJob with template interpolation";
      else if (QUERY_TPL.test(line)) label = "Analytics .query() with template interpolation";
      else if (EXEC_TPL.test(line))
        label = ".execute() with template interpolation in analytics context";
      if (!label) continue;
      const start = Math.max(0, i - 1);
      const end = Math.min(lines.length, i + 3);
      matches.push({
        vulnSlug: "snowflake-bigquery-sql",
        lineNumbers: [i + 1],
        snippet: lines.slice(start, end).join("\n"),
        matchedPattern: label,
      });
    }
    return matches;
  },
};

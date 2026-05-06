import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Salesforce SOQL injection. The jsforce / @jsforce/jsforce-node `query()`
 * method takes a raw SOQL string. Template-literal interpolation of
 * caller-controlled values into that string is exploitable the same way
 * SQL injection is — Salesforce evaluates the SOQL as written.
 *
 * Flags:
 *   - `conn.query(\`...${...}...\`)` / `conn.queryAll(...)` patterns
 *   - `tooling.query(...)` (Tooling API)
 *   - `sf.query(...)` / `salesforce.query(...)` aliases
 *   - String concat building SOQL: `"SELECT ... FROM ... WHERE " + name`
 */
export const soqlInjectionMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "soql-injection",
  description: "Salesforce SOQL built with template/string interpolation",
  filePatterns: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.mjs"],
  requires: { tech: ["apex", "salesforce"] },
  examples: [
    `import jsforce from "jsforce";\nawait conn.query(\`SELECT Id FROM Account WHERE Name = '\${name}'\`);`,
    `import jsforce from "jsforce";\nawait conn.queryAll(\`SELECT Id FROM Lead WHERE Email = '\${email}'\`);`,
    `import jsforce from "jsforce";\nawait conn.query("SELECT Id FROM Account WHERE Id = " + id);`,
    `import { Connection } from "@jsforce/jsforce-node";\nawait sf.query(\`SELECT Id FROM Account WHERE Id = '\${id}'\`);`,
    `import jsforce from "jsforce";\nawait tooling.query(\`SELECT Id FROM ApexClass WHERE Name = '\${name}'\`);`,
    `import { something } from "@salesforce/api";\nconst soql = \`SELECT Id FROM Account WHERE Name = '\${name}'\`;`,
    `import jsforce from "jsforce";\nawait sfConn.queryMore(\`SELECT Id FROM Lead WHERE Status = '\${status}'\`);`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)$/.test(filePath)) return [];
    if (/\.d\.ts$/.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    // Salesforce context: import jsforce, @jsforce/*, or use sf./salesforce. namespace
    const HAS_SF =
      /\bfrom\s+["'](?:jsforce[^"']*|@jsforce\/[^"']*|@salesforce\/[^"']*)["']|\b(?:sf|salesforce|conn|sfConn)\.\s*query(?:All)?\s*\(/;
    if (!HAS_SF.test(content)) return [];

    const lines = content.split("\n");
    const matches: CandidateMatch[] = [];

    // .query/.queryAll/.queryMore with template literal that interpolates
    const TPL = /\b(?:sf|salesforce|conn|sfConn|tooling)\.\s*query(?:All|More)?\s*\(\s*`[^`]*\$\{/;
    // .query with string concat
    const CONCAT =
      /\b(?:sf|salesforce|conn|sfConn|tooling)\.\s*query(?:All|More)?\s*\(\s*["'][^"']*["']\s*\+/;
    // Outside helpers: a SOQL-shape string with interpolation
    const SOQL_TPL = /`(?:[^`]*?\bSELECT\s+[^`]*?\bFROM\s+[A-Za-z_][A-Za-z0-9_]*[^`]*?)\$\{/i;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      let label: string | undefined;
      if (TPL.test(line)) label = "SOQL via template literal — possible SOQL injection";
      else if (CONCAT.test(line)) label = "SOQL via string concat — possible SOQL injection";
      else if (SOQL_TPL.test(line)) label = "SOQL-shaped template literal with interpolation";
      if (!label) continue;
      const start = Math.max(0, i - 1);
      const end = Math.min(lines.length, i + 3);
      matches.push({
        vulnSlug: "soql-injection",
        lineNumbers: [i + 1],
        snippet: lines.slice(start, end).join("\n"),
        matchedPattern: label,
      });
    }
    return matches;
  },
};

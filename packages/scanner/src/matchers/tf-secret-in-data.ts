import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * `kubernetes_secret` resource whose `data` block contains literal string
 * values instead of references to encrypted vars. Hardcoded plaintext in
 * tf source = plaintext in the Terraform Cloud state file.
 *
 * Acceptable patterns (NOT flagged):
 *   - `module.vercel_encryption.encrypted_secrets[...]`
 *   - `var.<name>` (variable, presumably with sensitive=true upstream)
 *   - `local.<name>` referencing a sensitive local
 *   - `data.<provider>.<name>...` data-source lookups
 *   - `base64encode(file("..."))` from a checked-in cert/CA file
 *
 * Flagged: any string literal `= "...something..."` longer than ~12 chars.
 */
export const tfSecretInDataMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "tf-secret-in-data",
  description: "kubernetes_secret resource with hardcoded plaintext value in data block",
  filePatterns: ["**/*.tf"],
  requires: { tech: ["terraform"] },
  examples: [
    `resource "kubernetes_secret" "db" {\n  metadata { name = "db" }\n  data = {\n    password = "supersecret-plaintext-value"\n  }\n}`,
    `resource "kubernetes_secret_v1" "api" {\n  metadata { name = "api" }\n  data = {\n    api_key = "AKIAIOSFODNN7EXAMPLE"\n  }\n}`,
    `resource "kubernetes_secret" "tokens" {\n  metadata { name = "tokens" }\n  data = {\n    token = "REDACTED-plaintext-token-value-goes-here"\n  }\n}`,
  ],
  match(content) {
    const lines = content.split("\n");
    const hitLines: number[] = [];
    const snippets: string[] = [];

    let inSecret = false;
    let inData = false;
    let braceDepth = 0;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/^\s*resource\s+"kubernetes_secret(?:_v1)?"\s+/.test(line)) {
        inSecret = true;
        braceDepth = 0;
      }
      if (!inSecret) continue;

      // Track braces
      for (const ch of line) {
        if (ch === "{") braceDepth++;
        else if (ch === "}") {
          braceDepth--;
          if (braceDepth === 0) {
            inSecret = false;
            inData = false;
          }
        }
      }

      if (/^\s*data\s*=?\s*\{/.test(line)) inData = true;
      if (inData && braceDepth <= 1 && /^\s*\}/.test(line)) inData = false;

      if (!inData) continue;

      // Look for `key = "literal-value"` lines that aren't references
      const m = line.match(/^\s*[\w-]+\s*=\s*"([^"]+)"/);
      if (!m) continue;
      const value = m[1];
      // Skip references
      if (/\$\{[^}]+\}/.test(value)) continue;
      // Skip very short values (probably innocuous tags / labels)
      if (value.length < 8) continue;
      // Skip common safe values
      if (/^(default|true|false|enabled|disabled|none|public|private)$/i.test(value)) continue;
      hitLines.push(i + 1);
      const s = Math.max(0, i - 1);
      const e = Math.min(lines.length, i + 2);
      snippets.push(lines.slice(s, e).join("\n"));
    }

    if (hitLines.length === 0) return [];
    const match: CandidateMatch = {
      vulnSlug: "tf-secret-in-data",
      lineNumbers: hitLines,
      snippet: snippets[0],
      matchedPattern: "kubernetes_secret.data with literal value",
    };
    return [match];
  },
};

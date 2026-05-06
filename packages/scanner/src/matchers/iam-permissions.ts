import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Front repo: Finds withAuthentication() calls to audit IAM permission
 * configurations. Misconfigured permissions can lead to privilege escalation.
 */
export const iamPermissionsMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "iam-permissions",
  description: "withAuthentication/IAM permission checks — audit for correct Action/Resource pairs",
  filePatterns: [
    "**/app/api/**/route.{ts,tsx}",
    "**/app/**/actions.{ts,tsx}",
    "**/api/**/*.{ts,tsx}",
  ],
  examples: [
    `export const POST = withAuthentication(handler, opts);`,
    `const wrapped = withAuthentication(handler);`,
    `const a = Action.READ_PROJECT.with(Resource.PROJECT);`,
    `if (Action.UPDATE_TEAM && Resource.TEAM) ok();`,
    `const opts = { permissions: [Action.READ.PROJECT] };`,
    `permissions: [`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    const patterns: { regex: RegExp; label: string }[] = [
      {
        regex: /withAuthentication\s*\(/,
        label: "withAuthentication IAM wrapper (verify permissions)",
      },
      {
        regex: /Action\.\w+.*Resource\.\w+/,
        label: "IAM Action/Resource pair (verify correctness)",
      },
      {
        regex: /permissions:\s*\[/,
        label: "Permissions array (verify completeness)",
      },
    ];

    for (const { regex, label } of patterns) {
      for (let i = 0; i < lines.length; i++) {
        if (regex.test(lines[i])) {
          const start = Math.max(0, i - 2);
          const end = Math.min(lines.length, i + 3);
          matches.push({
            vulnSlug: "iam-permissions",
            lineNumbers: [i + 1],
            snippet: lines.slice(start, end).join("\n"),
            matchedPattern: label,
          });
        }
      }
    }

    return matches;
  },
};

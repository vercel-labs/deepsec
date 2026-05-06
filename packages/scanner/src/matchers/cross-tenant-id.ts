import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

export const crossTenantIdMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "cross-tenant-id",
  description:
    "User-supplied IDs used in DB lookups without ownership verification — cross-tenant risk",
  filePatterns: [
    "**/services/**/endpoints/**/*.ts",
    "**/services/**/endpoint/**/*.ts",
    "**/services/**/src/index.ts",
    "**/apps/**/route.ts",
    "**/apps/**/route.*.ts",
    "**/app/api/**/*.ts",
  ],
  examples: [
    `const t = await getTeamById(parsed.body.teamId);`,
    `const u = await getUserById(req.params.userId);`,
    `const i = await getInstallationByUid(parsed.query.installationUid);`,
    `const teamId = parsed.body.teamId;`,
    `const ownerId = req.params.ownerId;`,
    `const userId = parsed.query.userId;`,
    `const installationId = parsed.body.installationId;`,
    `const configurationId = parsed.body.configurationId;`,
    `const integrationConfigurationId = req.body.integrationConfigurationId;`,
    `const t = getTeamById(install.ownerId);`,
    `const t = getTeamById(record.teamId);`,
    `const r = await findById(parsed.params.id);`,
    `const r = await findOneById(req.body.id);`,
    `const r = await findByUid(parsed.body.uid);`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    const patterns: { regex: RegExp; label: string }[] = [
      {
        regex: /get\w+By(Id|Uid)\s*\(\s*(parsed\.(body|query|params)|req\.(body|query|params))/,
        label: "DB lookup with user-supplied ID from request",
      },
      {
        regex:
          /(teamId|ownerId|userId|installationId|configurationId|integrationConfigurationId)\s*[:=]\s*(parsed|req)\.(body|query|params)/,
        label: "Tenant/user ID extracted from request input",
      },
      {
        regex: /getTeamById\s*\(\s*\w+\.(ownerId|teamId)/,
        label: "getTeamById with potentially unverified ownerId",
      },
      {
        regex: /find(One)?By(Id|Uid)\s*\(\s*(parsed|req)\./,
        label: "findById with user-supplied ID",
      },
    ];

    for (const { regex, label } of patterns) {
      for (let i = 0; i < lines.length; i++) {
        if (regex.test(lines[i])) {
          const start = Math.max(0, i - 2);
          const end = Math.min(lines.length, i + 3);
          matches.push({
            vulnSlug: "cross-tenant-id",
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

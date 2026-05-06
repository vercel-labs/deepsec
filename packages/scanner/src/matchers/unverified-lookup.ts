import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

export const unverifiedLookupMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "unverified-lookup",
  description: "DB lookups by ID without a nearby ownership check — cross-tenant risk",
  filePatterns: [
    "**/services/**/endpoints/**/*.ts",
    "**/services/**/endpoint/**/*.ts",
    "**/services/**/src/index.ts",
    "**/apps/**/route.ts",
    "**/apps/**/route.*.ts",
    "**/app/api/**/*.ts",
    "**/src/**/*.ts",
  ],
  examples: [
    `const project = await getProjectById(projectId);
return Response.json(project);`,
    `const team = await getTeamById(teamId);
return Response.json(team);`,
    `const user = await getUserById(userId);
return Response.json(user);`,
    `const deployment = await getDeploymentById(id);
return Response.json(deployment);`,
    `const installation = await getInstallationById(id);
return Response.json(installation);`,
    `const data = await db.findUnique({ where: { id } });
return Response.json(data);`,
    `const data = await db.findFirst({ where: { id } });
return Response.json(data);`,
    `const r = await repo.findOneById(id);
return Response.json(r);`,
    `const r = await repo.findByUid(uid);
return Response.json(r);`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    const lookupPatterns = [
      /get\w+By(Id|Uid)\s*\(/,
      /find(One)?By(Id|Uid)\s*\(/,
      /getTeamById\s*\(/,
      /getUserById\s*\(/,
      /getProjectById\s*\(/,
      /getDeploymentById\s*\(/,
      /getInstallationById\s*\(/,
      /\.findUnique\s*\(/,
      /\.findFirst\s*\(/,
    ];

    const ownershipChecks = [
      /===?\s*auth\.|auth\.\w+\s*===?/,
      /ownerId\s*===?|===?\s*ownerId/,
      /\.teamId\s*===?|===?\s*\.teamId/,
      /\.userId\s*===?|===?\s*\.userId/,
      /throw.*403|throw.*Forbidden|throw.*Unauthorized/,
      /auth\.can\s*\(/,
      /if\s*\(\s*!\s*(installation|project|team|deployment)\./,
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const isLookup = lookupPatterns.some((p) => p.test(line));
      if (!isLookup) continue;

      // Check the next 15 lines for an ownership check
      const window = lines.slice(i, Math.min(lines.length, i + 15)).join("\n");
      const hasOwnershipCheck = ownershipChecks.some((p) => p.test(window));

      if (!hasOwnershipCheck) {
        const start = Math.max(0, i - 1);
        const end = Math.min(lines.length, i + 4);
        matches.push({
          vulnSlug: "unverified-lookup",
          lineNumbers: [i + 1],
          snippet: lines.slice(start, end).join("\n"),
          matchedPattern: "DB lookup by ID without ownership check in next 15 lines",
        });
      }
    }

    return matches;
  },
};

import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

export const useServerExportMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "use-server-export",
  description:
    "Server Action files that export functions accepting identity/auth objects as parameters — trusting client input",
  filePatterns: ["**/*.{ts,tsx}"],
  requires: { tech: ["nextjs"] },
  examples: [
    `"use server";\nexport async function deletePost(owner: string, postId: string) { return { owner, postId } }`,
    `'use server'\nexport async function transferFunds(authenticatedOwner, target, amount) { return { authenticatedOwner } }`,
    `"use server";\nexport function getProfile(user) { return user }`,
    `'use server'\nexport async function logEvent(session: any, event: string) { return { session, event } }`,
    `"use server";\nexport function setRole(actor, role) { return { actor, role } }`,
    `'use server'\nexport async function audit(caller: string, action: string) { return { caller, action } }`,
    `"use server";\nexport async function actAs(\n  identity: string,\n  payload: any,\n) { return { identity, payload } }`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    // Must have 'use server' directive
    if (!/['"]use server['"]/.test(content)) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    const identityParams =
      /\b(owner|authenticatedOwner|user|auth|session|identity|actor|caller)\b/i;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      // Exported function with identity-like parameter
      if (/export\s+(async\s+)?function\s+\w+/.test(line)) {
        // Check the function signature (may span multiple lines)
        const sigLines = lines.slice(i, Math.min(lines.length, i + 5)).join(" ");
        if (identityParams.test(sigLines)) {
          const start = Math.max(0, i - 1);
          const end = Math.min(lines.length, i + 4);
          matches.push({
            vulnSlug: "use-server-export",
            lineNumbers: [i + 1],
            snippet: lines.slice(start, end).join("\n"),
            matchedPattern:
              "Server Action exports function accepting identity/auth parameter — client can supply arbitrary values",
          });
        }
      }
    }

    return matches;
  },
};

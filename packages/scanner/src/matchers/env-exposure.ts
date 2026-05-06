import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Both repos: Detects potential environment variable exposure.
 * NEXT_PUBLIC_ vars are sent to the client — verify they don't contain secrets.
 * Also flags patterns where secrets may leak to client bundles.
 */
export const envExposureMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "env-exposure",
  description: "Environment variable patterns that may expose secrets to clients",
  filePatterns: ["**/*.{ts,tsx,js,jsx}", "**/.env", "**/.env.*", "**/next.config.*"],
  examples: [
    `const k = process.env.NEXT_PUBLIC_API_SECRET;`,
    `const t = process.env.NEXT_PUBLIC_AUTH_TOKEN;`,
    `const p = process.env.NEXT_PUBLIC_USER_PASSWORD;`,
    `const c = process.env.NEXT_PUBLIC_OAUTH_CREDENTIAL;`,
    `const k = process.env.NEXT_PUBLIC_STRIPE_KEY;`,
    `"use client";\nconst s = process.env.API_SECRET;`,
    `'use client';\nconst k = process.env.PRIVATE_KEY;`,
    `"use client";\nconst t = process.env.AUTH_TOKEN;`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // NEXT_PUBLIC_ vars with suspicious names
      if (/NEXT_PUBLIC_.*(SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL)/i.test(line)) {
        const start = Math.max(0, i - 1);
        const end = Math.min(lines.length, i + 2);
        matches.push({
          vulnSlug: "env-exposure",
          lineNumbers: [i + 1],
          snippet: lines.slice(start, end).join("\n"),
          matchedPattern: "NEXT_PUBLIC_ variable with secret-like name",
        });
      }

      // process.env access in client components
      if (
        /process\.env\.\w*(SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL|PRIVATE)/i.test(line) &&
        /['"]use client['"]/.test(content)
      ) {
        const start = Math.max(0, i - 1);
        const end = Math.min(lines.length, i + 2);
        matches.push({
          vulnSlug: "env-exposure",
          lineNumbers: [i + 1],
          snippet: lines.slice(start, end).join("\n"),
          matchedPattern: "Secret env var accessed in 'use client' component",
        });
      }

      // .env files with actual values (not placeholders)
      if (/\.env/.test(filePath)) {
        if (
          /^[A-Z_]+=.{8,}/.test(line) &&
          !/^#/.test(line) &&
          !/<|placeholder|example|xxx/i.test(line)
        ) {
          if (/(SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL|PRIVATE)/i.test(line)) {
            matches.push({
              vulnSlug: "env-exposure",
              lineNumbers: [i + 1],
              snippet: line,
              matchedPattern: "Secret value in committed .env file",
            });
          }
        }
      }
    }

    return matches;
  },
};

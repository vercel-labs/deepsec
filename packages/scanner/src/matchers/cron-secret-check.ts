import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

export const cronSecretCheckMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "cron-secret-check",
  description:
    "Cron endpoints — verify CRON_SECRET validation is present and not bypassable when env unset",
  filePatterns: [
    "**/cron/**/*.{ts,tsx,js,jsx}",
    "**/crons/**/*.{ts,tsx,js,jsx}",
    "**/api/cron*/**/*.{ts,tsx,js,jsx}",
    "**/app/api/**/route.{ts,tsx}",
  ],
  examples: [
    `// CRON_SECRET check on cron route
export async function GET(req: Request) {
  if (req.headers.get("authorization") !== \`Bearer \${process.env.CRON_SECRET}\`) {
    return new Response("unauthorized", { status: 401 });
  }
  return new Response("ok");
}`,
    `// CRON_SECRET handler
export const POST = async (req) => {
  const secret = process.env.CRON_SECRET;
  if (req.headers.get("x-cron-secret") !== secret) {
    return new Response("nope", { status: 401 });
  }
  return Response.json({ ok: true });
};`,
    `// cron auth via CRON_SECRET
export async function GET(req) {
  const auth = req.headers.get("authorization");
  if (auth !== \`Bearer \${process.env.CRON_SECRET}\`) return new Response(null, { status: 401 });
  await runCron();
  return new Response("done");
}`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];
    // Only match files in cron paths or files that reference CRON_SECRET
    if (!/cron/i.test(filePath) && !/CRON_SECRET/.test(content)) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    const isCronRoute = /cron/i.test(filePath);
    const hasCronSecret = /CRON_SECRET/.test(content);
    const hasHandler =
      /export\s+(async\s+)?function\s+(GET|POST)|export\s+(const\s+)?(GET|POST)/.test(content);

    if (isCronRoute && hasHandler) {
      if (!hasCronSecret) {
        // Cron route without any CRON_SECRET check
        for (let i = 0; i < lines.length; i++) {
          if (/export\s+(async\s+)?function|export\s+(const\s+)?(GET|POST)/.test(lines[i])) {
            const start = Math.max(0, i - 1);
            const end = Math.min(lines.length, i + 3);
            matches.push({
              vulnSlug: "cron-secret-check",
              lineNumbers: [i + 1],
              snippet: lines.slice(start, end).join("\n"),
              matchedPattern: "Cron route handler without CRON_SECRET validation",
            });
            break;
          }
        }
      } else {
        // Has CRON_SECRET but check if it's bypassable when env unset
        for (let i = 0; i < lines.length; i++) {
          if (/CRON_SECRET/.test(lines[i])) {
            const start = Math.max(0, i - 2);
            const end = Math.min(lines.length, i + 3);
            matches.push({
              vulnSlug: "cron-secret-check",
              lineNumbers: [i + 1],
              snippet: lines.slice(start, end).join("\n"),
              matchedPattern: "CRON_SECRET check (verify not bypassable when env var unset)",
            });
          }
        }
      }
    }

    return matches;
  },
};

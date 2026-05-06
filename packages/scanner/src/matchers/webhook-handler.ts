import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Both repos: Webhook handlers are public-facing endpoints that accept
 * external payloads. Must verify signatures to prevent spoofing.
 */
export const webhookHandlerMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "webhook-handler",
  description: "Webhook endpoints that receive external payloads — must verify signatures",
  filePatterns: [
    "**/*webhook*/**/*.{ts,tsx,js,jsx}",
    "**/*hook*/**/route.{ts,js}",
    "**/api/**/route.{ts,js}",
    "**/services/**/src/**/*.ts",
  ],
  examples: [
    `export async function POST(req) { /* webhook */ return ok(); }`,
    `export const handler = async (req) => { /* webhook */ };`,
    `// webhook route\nexport function POST(req) { return ok(); }`,
    `export async function webhookHandler(req) { return ok(); }`,
    `export const webhookRoute = (req) => process(req);`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    // Only match files that look like webhook handlers
    const isWebhook =
      /webhook/i.test(filePath) || /webhook/i.test(content) || /hook.*route/i.test(filePath);

    if (!isWebhook) return [];

    const patterns: { regex: RegExp; label: string }[] = [
      { regex: /webhook/i, label: "Webhook handler (verify signature validation)" },
    ];

    // Check if signature verification is present
    const hasVerification =
      /verifySignature|verify.*signature|hmac|createHmac|timingSafeEqual/i.test(content);

    for (const { regex, label } of patterns) {
      for (let i = 0; i < lines.length; i++) {
        if (regex.test(lines[i]) && /export|handler|POST|route/i.test(lines[i])) {
          const start = Math.max(0, i - 2);
          const end = Math.min(lines.length, i + 3);
          matches.push({
            vulnSlug: "webhook-handler",
            lineNumbers: [i + 1],
            snippet: lines.slice(start, end).join("\n"),
            matchedPattern: hasVerification
              ? `${label} — has signature verification`
              : `${label} — NO signature verification found`,
          });
          break; // One match per file is enough
        }
      }
    }

    return matches;
  },
};

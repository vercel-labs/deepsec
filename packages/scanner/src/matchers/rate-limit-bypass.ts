import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Both repos: Finds endpoints that may lack rate limiting.
 * Sensitive operations (auth, billing, data export) without rate limits
 * can be abused for brute-force, DoS, or data scraping.
 */
export const rateLimitBypassMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "rate-limit-bypass",
  description: "Sensitive endpoints that may lack rate limiting",
  filePatterns: [
    "**/app/api/**/route.{ts,tsx}",
    "**/apps/**/route.{ts,tsx}",
    "**/apps/**/route.*.ts",
    "**/services/**/endpoints/**/*.ts",
    "**/services/**/src/index.ts",
    "**/pages/api/**/*.{ts,tsx}",
  ],
  examples: [
    `// login handler\nexport const POST = async (req) => signIn(req);`,
    `// password reset\nexport async function POST(req) { return resetPassword(req); }`,
    `// billing charge\nexport default async function (req, res) { charge(req); }`,
    `// delete account\nexport const DELETE = (req) => removeUser(req);`,
    `// data export\nexport default async function handler(req, res) { exportData(); }`,
    `// generate token\nexport const POST = async (req) => createToken(req);`,
    `// invite member\nexport default function handler(req, res) { invite(req); }`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    // Detect sensitive operations
    const sensitivePatterns = [
      /login|signin|sign.in|authenticate/i,
      /password|passwd|reset.*password/i,
      /billing|charge|payment|refund|invoice/i,
      /delete.*account|remove.*user|deactivate/i,
      /export|download.*data|bulk/i,
      /api.key|token.*create|generate.*token/i,
      /invite|add.*member|transfer.*ownership/i,
    ];

    const isSensitive = sensitivePatterns.some((p) => p.test(content) || p.test(filePath));

    if (!isSensitive) return [];

    // Check for rate limiting
    const hasRateLimit = /rateLimit|rate.limit|checkRateLimit|rateLimiter|throttle/i.test(content);

    if (hasRateLimit) return []; // Has rate limiting, skip

    // Find the handler definition
    const handlerPatterns = [
      /export\s+(const\s+)?(GET|POST|PUT|DELETE|PATCH)\s*=/,
      /export\s+(async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH)/,
      /export\s+default/,
      /withSchema\s*\(/,
      /withAuthentication\s*\(/,
    ];

    for (let i = 0; i < lines.length; i++) {
      if (handlerPatterns.some((p) => p.test(lines[i]))) {
        const start = Math.max(0, i - 1);
        const end = Math.min(lines.length, i + 4);
        matches.push({
          vulnSlug: "rate-limit-bypass",
          lineNumbers: [i + 1],
          snippet: lines.slice(start, end).join("\n"),
          matchedPattern: "Sensitive endpoint without rate limiting",
        });
        break; // One per file
      }
    }

    return matches;
  },
};

import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

export const missingAuthMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "missing-auth",
  description: "All HTTP request entry points — flagged as weak candidates for auth review",
  filePatterns: [
    "**/api/**/*.{ts,tsx,js,jsx}",
    "**/app/api/**/*.{ts,tsx,js,jsx}",
    "**/pages/api/**/*.{ts,tsx,js,jsx}",
    "**/routes/**/*.{ts,tsx,js,jsx}",
    "**/server/**/*.{ts,tsx,js,jsx}",
    "**/*.{ts,tsx,js,jsx}", // catch-all for non-standard layouts
  ],
  examples: [
    `export async function GET(req) { return Response.json({}); }`,
    `export function POST(req) { return new Response(""); }`,
    `export const GET = async () => Response.json({});`,
    `export let PUT = (req) => new Response("");`,
    `export default async function handler(req, res) { res.json({}); }`,
    `export default function (req, res) { res.end(); }`,
    `router.get("/items", (req, res) => res.json([]));`,
    `app.post("/login", handler);`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    // Skip files that use backend framework auth wrappers (these are properly protected)
    // Note: Next.js middleware.ts is NOT considered sufficient — only direct handler wrappers count
    const hasBackendAuth = [
      /withSchema\s*\(/,
      /withAuthentication\s*\(/,
      /authMiddleware/,
      /withAuth\s*\(/,
      /requireAuth/,
      /authTeamOrUserReq/,
      /performOIDCOrTeamOrUserAuth/,
    ].some((p) => p.test(content));

    if (hasBackendAuth) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    // Patterns that indicate an HTTP entry point
    const handlerPatterns: { regex: RegExp; label: string }[] = [
      // Next.js App Router route handlers
      {
        regex: /export\s+(async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/,
        label: "Next.js App Router handler",
      },
      {
        regex: /export\s+(const|let)\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*=/,
        label: "Next.js App Router handler (arrow)",
      },
      // Next.js Pages API routes
      {
        regex: /export\s+default\s+(async\s+)?function/,
        label: "default export handler",
      },
      // Express / Fastify / Hono style
      {
        regex: /router\.(get|post|put|patch|delete|all)\s*\(/,
        label: "router method handler",
      },
      {
        regex: /app\.(get|post|put|patch|delete|all)\s*\(/,
        label: "app method handler",
      },
      // Hono
      {
        regex: /\.route\s*\(\s*['"]\//,
        label: "route definition",
      },
    ];

    for (const { regex, label } of handlerPatterns) {
      for (let i = 0; i < lines.length; i++) {
        if (regex.test(lines[i])) {
          const start = Math.max(0, i - 2);
          const end = Math.min(lines.length, i + 3);
          matches.push({
            vulnSlug: "missing-auth",
            lineNumbers: [i + 1],
            snippet: lines.slice(start, end).join("\n"),
            matchedPattern: `HTTP entry point: ${label} (weak candidate)`,
          });
        }
      }
    }

    return matches;
  },
};

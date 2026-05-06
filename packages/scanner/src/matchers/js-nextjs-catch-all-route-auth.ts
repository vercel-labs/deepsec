import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

export const catchAllRouteAuthMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "catch-all-route-auth",
  description: "Catch-all routes and Payload CMS endpoints — verify auth covers all sub-paths",
  filePatterns: [
    "**/[[...rest]]/**/*.{ts,tsx}",
    "**/[...slug]/**/*.{ts,tsx}",
    "**/[...path]/**/*.{ts,tsx}",
    "**/(payload)/**/*.{ts,tsx}",
    "**/graphql/route.{ts,tsx}",
    "**/app/api/**/*.{ts,tsx}",
  ],
  requires: { tech: ["nextjs"] },
  examples: [
    `export async function GET(request) { return Response.json({}) }`,
    `export async function POST(request: Request) { const body = await request.json(); return Response.json(body) }`,
    `export const PUT = async (req) => Response.json({})`,
    `export const PATCH = async (req: Request) => Response.json({})`,
    `export function DELETE(request) { return new Response(null, { status: 204 }) }`,
    `export async function GET() { await requireAuth(); return Response.json({}) }`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    const isCatchAll = /\[\[\.\.\.|\[\.\.\./.test(filePath);
    const isPayload =
      /\(payload\)|payload.*graphql|GRAPHQL_POST|GRAPHQL_GET/.test(content) ||
      /\(payload\)/.test(filePath);
    const isGraphQL = /graphql/i.test(filePath);

    if (!isCatchAll && !isPayload && !isGraphQL) return [];

    const hasAuth = [
      /withAuthentication\s*\(/,
      /withSchema\s*\(/,
      /getSession\s*\(/,
      /auth\s*\(\s*\)/,
      /requireAuth/,
      /verifyToken/,
    ].some((p) => p.test(content));

    for (let i = 0; i < lines.length; i++) {
      if (
        /export\s+(async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH)|export\s+(const\s+)?(GET|POST|PUT|DELETE|PATCH)\s*=/.test(
          lines[i],
        )
      ) {
        const start = Math.max(0, i - 1);
        const end = Math.min(lines.length, i + 3);
        const label = isCatchAll
          ? `Catch-all route handler${hasAuth ? " (has auth)" : " — NO auth on catch-all"}`
          : isPayload || isGraphQL
            ? `Payload/GraphQL endpoint${hasAuth ? " (has auth)" : " — NO auth"}`
            : "Route handler";
        matches.push({
          vulnSlug: "catch-all-route-auth",
          lineNumbers: [i + 1],
          snippet: lines.slice(start, end).join("\n"),
          matchedPattern: label,
        });
        break;
      }
    }

    return matches;
  },
};

import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

export const nextjsMiddlewareOnlyAuthMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "nextjs-middleware-only-auth",
  description:
    "Route handlers in protected route groups without their own auth check — relying solely on Next.js middleware",
  filePatterns: [
    "**/app/**(protected)**/route.{ts,tsx}",
    "**/app/**(dashboard)**/route.{ts,tsx}",
    "**/app/**(auth)**/route.{ts,tsx}",
    "**/app/api/**/route.{ts,tsx}",
  ],
  requires: { tech: ["nextjs"] },
  examples: [
    `export async function GET(request) { return Response.json({ ok: true }) }`,
    `export async function POST(request: Request) { const body = await request.json(); return Response.json(body) }`,
    `export const PUT = async (req) => Response.json({})`,
    `export const PATCH = async (req: Request) => Response.json({})`,
    `export function DELETE(request) { return new Response(null, { status: 204 }) }`,
    `export const GET = async () => Response.json([])`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    // Only match route handlers
    const isRoute = /route\.(ts|tsx)$/.test(filePath);
    if (!isRoute) return [];

    const hasHandler =
      /export\s+(async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)|export\s+(const\s+)?(GET|POST|PUT|PATCH|DELETE)\s*=/.test(
        content,
      );
    if (!hasHandler) return [];

    // Check for backend auth wrappers — these are OK
    const hasBackendAuth = [
      /withSchema\s*\(/,
      /withAuthentication\s*\(/,
      /getSession\s*\(/,
      /auth\s*\(\s*\)/,
      /requireAuth/,
      /verifyToken/,
      /authMiddleware/,
      /withAuth\s*\(/,
    ].some((p) => p.test(content));

    if (hasBackendAuth) return [];

    // This route has no backend auth — it relies on middleware.ts
    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    const isProtectedGroup = /\(protected\)|\(dashboard\)|\(auth\)/.test(filePath);

    for (let i = 0; i < lines.length; i++) {
      if (
        /export\s+(async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)|export\s+(const\s+)?(GET|POST|PUT|PATCH|DELETE)\s*=/.test(
          lines[i],
        )
      ) {
        const start = Math.max(0, i - 1);
        const end = Math.min(lines.length, i + 3);
        matches.push({
          vulnSlug: "nextjs-middleware-only-auth",
          lineNumbers: [i + 1],
          snippet: lines.slice(start, end).join("\n"),
          matchedPattern: isProtectedGroup
            ? "Route in protected group with no backend auth — relies solely on Next.js middleware"
            : "API route without backend auth check (weak candidate)",
        });
        break;
      }
    }

    return matches;
  },
};

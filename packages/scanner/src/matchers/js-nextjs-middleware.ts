import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Next.js middleware files are security-critical — they handle auth redirects,
 * CSRF, bot detection, header rewriting, and path-based access control.
 * A broken middleware = bypassed auth for entire route groups.
 */
export const nextjsMiddlewareMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "nextjs-middleware",
  description: "Next.js middleware.ts files — auth, redirects, header rewriting, access control",
  filePatterns: ["**/middleware.{ts,tsx,js,jsx}"],
  requires: { tech: ["nextjs"] },
  examples: [
    `export function middleware(request) { return NextResponse.next() }`,
    `export async function middleware(request: NextRequest) { return NextResponse.redirect(new URL('/login', request.url)) }`,
    `export const middleware = (req) => NextResponse.next()`,
    `export let middleware = async (req) => NextResponse.rewrite(new URL('/foo', req.url))`,
    `export default function middleware(request) { return NextResponse.next() }`,
    `export default async function (req) { return NextResponse.next() }`,
    `export function middleware(req) { return NextResponse.next() }\nexport const config = { matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'] }`,
    `export default function middleware(req) { return NextResponse.next() }\nexport const config = { matcher: '/dashboard/:path*' }`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    // Must have a middleware export or default export
    const hasMiddleware =
      /export\s+(default\s+|async\s+)?function\s+middleware/i.test(content) ||
      /export\s+(const|let)\s+middleware/i.test(content) ||
      /export\s+default/.test(content);

    if (!hasMiddleware) return [];

    // Flag the middleware function itself
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (
        /export\s+(default\s+|async\s+)?function\s+middleware/i.test(line) ||
        /export\s+(const|let)\s+middleware/i.test(line) ||
        /export\s+default\s+(async\s+)?function/.test(line)
      ) {
        const start = Math.max(0, i - 1);
        const end = Math.min(lines.length, i + 6);
        matches.push({
          vulnSlug: "nextjs-middleware",
          lineNumbers: [i + 1],
          snippet: lines.slice(start, end).join("\n"),
          matchedPattern: "Next.js middleware — security-critical request interceptor",
        });
      }
    }

    // Flag matcher config (controls which routes the middleware applies to)
    for (let i = 0; i < lines.length; i++) {
      if (/export\s+const\s+config/.test(lines[i])) {
        const start = Math.max(0, i);
        const end = Math.min(lines.length, i + 10);
        matches.push({
          vulnSlug: "nextjs-middleware",
          lineNumbers: [i + 1],
          snippet: lines.slice(start, end).join("\n"),
          matchedPattern: "Middleware route matcher config — controls scope of protection",
        });
      }
    }

    return matches;
  },
};

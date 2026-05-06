import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Comprehensive route handler coverage. Every route.ts file is an HTTP endpoint.
 * Flags all exported HTTP method handlers (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS).
 */
export const allRouteHandlersMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "all-route-handlers",
  description: "All route.ts HTTP handlers — comprehensive entry point coverage (weak candidate)",
  filePatterns: ["**/route.{ts,tsx,js,jsx}", "**/route.*.{ts,tsx,js,jsx}"],
  requires: { tech: ["nextjs"] },
  examples: [
    `export async function GET(request) { return Response.json({}) }`,
    `export async function POST(request: Request) { return Response.json({ ok: true }) }`,
    `export const PUT = async (req) => Response.json({})`,
    `export const PATCH = async (req: Request) => Response.json({})`,
    `export function DELETE(request) { return new Response(null, { status: 204 }) }`,
    `export async function HEAD(request) { return new Response() }`,
    `export const OPTIONS = (req) => new Response()`,
    `export default async function (req, res) { res.json({}) }`,
    `export default function (req, res) { res.send('ok') }`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Named exports: export const GET, export async function POST, etc.
      const methodMatch = line.match(
        /export\s+(?:const|async\s+function|function)\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/,
      );
      if (!methodMatch) continue;

      const method = methodMatch[1];
      const start = Math.max(0, i - 1);
      const end = Math.min(lines.length, i + 4);
      matches.push({
        vulnSlug: "all-route-handlers",
        lineNumbers: [i + 1],
        snippet: lines.slice(start, end).join("\n"),
        matchedPattern: `${method} route handler — HTTP entry point (weak candidate)`,
      });
    }

    // Also flag default exports (Lambda-style handlers)
    for (let i = 0; i < lines.length; i++) {
      if (/export\s+default\s+(async\s+)?(function\s*)?\(/.test(lines[i])) {
        const start = Math.max(0, i - 1);
        const end = Math.min(lines.length, i + 4);
        matches.push({
          vulnSlug: "all-route-handlers",
          lineNumbers: [i + 1],
          snippet: lines.slice(start, end).join("\n"),
          matchedPattern: "Default export route handler — HTTP entry point (weak candidate)",
        });
      }
    }

    return matches;
  },
};

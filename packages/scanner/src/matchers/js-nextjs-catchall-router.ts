import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Catch-all routes that funnel all API traffic through a single handler
 * with an internal router (Elysia, Hono, Express). Single point of failure
 * for auth — if the inner router misses a path, it's unprotected.
 */
export const catchallRouterMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "catchall-router",
  description:
    "Catch-all route with internal router (Elysia/Hono/Express) — single auth entry point",
  filePatterns: [
    "**/[[...rest]]/route.{ts,tsx}",
    "**/[[...slug]]/route.{ts,tsx}",
    "**/[...rest]/route.{ts,tsx}",
    "**/[...slug]/route.{ts,tsx}",
    "**/[[...catchAll]]/route.{ts,tsx}",
  ],
  requires: { tech: ["nextjs"] },
  examples: [
    `import { Elysia } from 'elysia';\nconst app = new Elysia();\nexport const GET = app.handle;`,
    `import { Hono } from 'hono';\nconst app = new Hono();\nexport const GET = (req) => app.fetch(req);`,
    `import express from 'express';\nconst app = express();\nexport const POST = (req) => app(req);`,
    `import { Router } from 'itty-router';\nconst router = Router();\nexport const GET = (req) => router.handle(req);`,
    `const router = createRouter();\nexport const GET = (req) => handleRequest(req);`,
    `export async function GET(request) { return Response.json({}) }`,
    `export const POST = async (req) => Response.json({})`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    // Detect internal routers
    const routerPatterns: { regex: RegExp; label: string }[] = [
      { regex: /from\s+['"]elysia['"]|new\s+Elysia/, label: "Elysia router in catch-all route" },
      { regex: /from\s+['"]hono['"]|new\s+Hono/, label: "Hono router in catch-all route" },
      { regex: /from\s+['"]express['"]|express\(\)/, label: "Express router in catch-all route" },
      { regex: /from\s+['"]itty-router['"]|Router\(\)/, label: "itty-router in catch-all route" },
      { regex: /createRouter|handleRequest/, label: "Custom router in catch-all route" },
    ];

    for (const { regex, label } of routerPatterns) {
      for (let i = 0; i < lines.length; i++) {
        if (regex.test(lines[i])) {
          const start = Math.max(0, i - 1);
          const end = Math.min(lines.length, i + 4);
          matches.push({
            vulnSlug: "catchall-router",
            lineNumbers: [i + 1],
            snippet: lines.slice(start, end).join("\n"),
            matchedPattern: label,
          });
          break; // One match per router type is enough
        }
      }
    }

    // Also flag the catch-all handler itself even without a known router
    if (matches.length === 0) {
      for (let i = 0; i < lines.length; i++) {
        if (
          /export\s+(const|async\s+function|function)\s+(GET|POST|PUT|PATCH|DELETE)\b/.test(
            lines[i],
          )
        ) {
          const start = Math.max(0, i - 1);
          const end = Math.min(lines.length, i + 4);
          matches.push({
            vulnSlug: "catchall-router",
            lineNumbers: [i + 1],
            snippet: lines.slice(start, end).join("\n"),
            matchedPattern: "Catch-all route handler — all sub-paths funneled here",
          });
        }
      }
    }

    return matches;
  },
};

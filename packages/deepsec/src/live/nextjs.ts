import fs from "node:fs";
import path from "node:path";
import {
  type AuthExpectation,
  type HttpMethod,
  type RouteSpec,
  routeId,
  routeSourceFingerprint,
} from "@deepsec/core";

/**
 * Next.js App Router surface extractor (Milestone 0: app-router first).
 *
 * Maps `app/**`/`route.ts` and `page.tsx`-style files to URL paths, infers the
 * HTTP methods each route exports, and makes a best-effort `authExpectation`
 * inference from the handler source. Pages are GET-only render surfaces; route
 * handlers (`route.ts`) can export any method handler.
 *
 * Deliberately deterministic and offline. Where it cannot tell whether a route
 * requires auth it reports `unknown` — honest unknown is more useful than a
 * wrong confident guess, and `unknown` routes are exactly what `live hunt`
 * probes (observing freely, claiming nothing).
 */

const ROUTE_FILE_RE = /(?:^|\/)route\.(?:ts|tsx|js|jsx|mjs|mts)$/;
const PAGE_FILE_RE = /(?:^|\/)page\.(?:tsx|jsx|mdx)$/;
const MIDDLEWARE_FILE_RE = /(?:^|\/)middleware\.(?:ts|js|mts)$/;

const HTTP_METHODS: readonly HttpMethod[] = [
  "GET",
  "HEAD",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "OPTIONS",
];

export interface NextjsExtractionResult {
  routes: RouteSpec[];
  /** Route-defining files seen, for the coverage report. */
  totalRouteFiles: number;
  /** Files the extractor saw but could not map to a route. */
  unmappedFiles: string[];
  /** Files that fed the fingerprint (route files + middleware + config). */
  inputFiles: string[];
}

/** True when a relative path is inside an app/ (or src/app/) directory. */
function inAppDir(rel: string): boolean {
  return /(?:^|\/)app\//.test(rel);
}

/**
 * Convert an app-router file path to its URL path.
 *   app/api/users/[id]/route.ts -> /api/users/[id]
 *   src/app/dashboard/page.tsx  -> /dashboard
 * Route groups `(marketing)` and the route-file segment itself are dropped.
 */
export function appFileToUrlPath(rel: string): string | null {
  const idx = rel.search(/(?:^|\/)app\//);
  if (idx === -1) return null;
  // Take everything after the "app/" marker, drop the trailing route file.
  const afterMarker = rel.slice(idx).replace(/^(?:.*\/)?app\//, "");
  const dir = path.posix.dirname(afterMarker);
  const segments = dir === "." ? [] : dir.split("/");
  // A private folder `_name` opts the whole subtree out of routing — a file
  // under one has no URL path at all (not a re-rooted one).
  if (segments.some((s) => s.startsWith("_"))) return null;
  const cleaned = segments
    .filter((s) => s !== "" && s !== ".")
    // Route groups `(name)` do not appear in the URL.
    .filter((s) => !(s.startsWith("(") && s.endsWith(")")));
  return "/" + cleaned.join("/");
}

/** Which HTTP methods a route file exports (from `export async function X` / `export const X`). */
function exportedMethods(source: string, isPage: boolean): HttpMethod[] {
  if (isPage) return ["GET"]; // pages render GET only
  const found = new Set<HttpMethod>();
  for (const m of HTTP_METHODS) {
    const re = new RegExp(`export\\s+(?:async\\s+)?(?:function|const|let)\\s+${m}\\b`);
    if (re.test(source)) found.add(m);
  }
  // HEAD/OPTIONS fall back to GET in Next when not explicitly defined.
  if (found.size === 0) found.add("GET");
  return [...found];
}

/**
 * Best-effort auth inference from handler source. Looks for an explicit auth /
 * session check before any response construction. This is intentionally
 * conservative: absence of a recognizable check yields `unknown`, never
 * `public` — only an unmistakable public marker yields `public`.
 */
function inferAuthExpectation(source: string): AuthExpectation {
  const authSignals = [
    /requireAuth\s*\(/,
    /getServerSession\s*\(/,
    /auth\s*\(\s*\)/,
    /verifySession\s*\(/,
    /currentUser\s*\(/,
    /unauthorized\s*\(\s*\)/i,
    /return\s+.*\b401\b/,
    /return\s+.*\b403\b/,
  ];
  const publicSignals = [
    /\/\*\s*@public\s*\*\//, // explicit escape hatch for authors
    /export\s+const\s+dynamic\s*=\s*"force-static"/, // static marketing pages
  ];
  if (publicSignals.some((r) => r.test(source))) return "public";
  if (authSignals.some((r) => r.test(source))) return "required";
  return "unknown";
}

/** Recursively collect route/page/middleware files under a directory. */
function walk(dir: string, base: string, out: string[]): void {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === "node_modules" || e.name.startsWith(".")) continue;
      walk(full, base, out);
    } else if (
      ROUTE_FILE_RE.test(e.name) ||
      PAGE_FILE_RE.test(e.name) ||
      MIDDLEWARE_FILE_RE.test(e.name)
    ) {
      out.push(path.relative(base, full).split(path.sep).join("/"));
    }
  }
}

/**
 * Extract the route surface from a Next.js app rooted at `root` (the repo
 * root; the extractor searches for app/ and src/app/ within it).
 */
export function extractNextjsSurface(root: string): NextjsExtractionResult {
  const files: string[] = [];
  walk(root, root, files);

  const routeFiles = files.filter(
    (f) => inAppDir(f) && (ROUTE_FILE_RE.test(f) || PAGE_FILE_RE.test(f)),
  );
  const middlewareFiles = files.filter((f) => MIDDLEWARE_FILE_RE.test(f));

  const routes: RouteSpec[] = [];
  const unmappedFiles: string[] = [];

  for (const rel of routeFiles.sort()) {
    const urlPath = appFileToUrlPath(rel);
    if (urlPath === null) {
      unmappedFiles.push(rel);
      continue;
    }
    const abs = path.join(root, rel);
    let source = "";
    try {
      source = fs.readFileSync(abs, "utf-8");
    } catch {
      unmappedFiles.push(rel);
      continue;
    }
    const isPage = PAGE_FILE_RE.test(rel);
    const methods = exportedMethods(source, isPage);
    routes.push({
      routeId: routeId(rel, urlPath, methods),
      path: urlPath,
      methods,
      definingFile: rel,
      authExpectation: inferAuthExpectation(source),
      sourceFingerprint: routeSourceFingerprint(source, `${rel}${urlPath}`),
    });
  }

  // Middleware participates in the surface fingerprint (it can enforce auth)
  // even though it is not itself a routable endpoint.
  const inputFiles = [...routeFiles, ...middlewareFiles].sort();

  return {
    routes,
    totalRouteFiles: routeFiles.length,
    unmappedFiles,
    inputFiles,
  };
}

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { appFileToUrlPath, extractNextjsSurface } from "../live/nextjs.js";
import { computeSurfaceFingerprint, recon } from "../live/recon.js";

describe("appFileToUrlPath", () => {
  it("maps route handlers to URL paths", () => {
    expect(appFileToUrlPath("app/api/users/[id]/route.ts")).toBe("/api/users/[id]");
    expect(appFileToUrlPath("app/api/health/route.ts")).toBe("/api/health");
  });

  it("maps pages and src/app roots", () => {
    expect(appFileToUrlPath("app/dashboard/page.tsx")).toBe("/dashboard");
    expect(appFileToUrlPath("src/app/page.tsx")).toBe("/");
  });

  it("drops route groups and excludes private-folder subtrees", () => {
    expect(appFileToUrlPath("app/(marketing)/about/page.tsx")).toBe("/about");
    // A `_private` folder opts the whole subtree out of routing (no URL).
    expect(appFileToUrlPath("app/_internal/secret/route.ts")).toBeNull();
  });

  it("returns null for non-app files", () => {
    expect(appFileToUrlPath("pages/api/x.ts")).toBeNull();
    expect(appFileToUrlPath("components/Button.tsx")).toBeNull();
  });
});

describe("extractNextjsSurface", () => {
  let root: string;
  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-recon-"));
  });
  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  function write(rel: string, content: string) {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }

  it("discovers route handlers with exported methods and auth inference", () => {
    write(
      "app/api/users/[id]/route.ts",
      `export async function GET() { return Response.json({}) }
       export async function DELETE() { return new Response(null, { status: 204 }) }`,
    );
    write(
      "app/api/admin/route.ts",
      `import { requireAuth } from "@/lib/auth"
       export async function GET() { await requireAuth(); return Response.json({}) }`,
    );
    write(
      "app/page.tsx",
      `export const dynamic = "force-static"; export default function P() { return null }`,
    );

    const { routes } = extractNextjsSurface(root);
    const byPath = Object.fromEntries(routes.map((r) => [r.path, r]));

    expect(byPath["/api/users/[id]"].methods.sort()).toEqual(["DELETE", "GET"]);
    expect(byPath["/api/users/[id]"].authExpectation).toBe("unknown");
    expect(byPath["/api/admin"].authExpectation).toBe("required");
    expect(byPath["/"].authExpectation).toBe("public");
    expect(byPath["/"].methods).toEqual(["GET"]);
  });

  it("produces stable routeIds and per-route fingerprints", () => {
    write("app/api/a/route.ts", `export async function GET() { return Response.json({}) }`);
    const a = extractNextjsSurface(root);
    const b = extractNextjsSurface(root);
    expect(a.routes[0].routeId).toBe(b.routes[0].routeId);
    expect(a.routes[0].sourceFingerprint).toBe(b.routes[0].sourceFingerprint);
  });

  it("counts coverage and leaves middleware out of routes but in the fingerprint inputs", () => {
    write("app/api/x/route.ts", `export async function GET() { return Response.json({}) }`);
    write("middleware.ts", `export function middleware() {}`);
    const result = extractNextjsSurface(root);
    expect(result.totalRouteFiles).toBe(1);
    expect(result.routes).toHaveLength(1);
    expect(result.inputFiles).toContain("middleware.ts");
  });
});

describe("computeSurfaceFingerprint / recon cache", () => {
  let root: string;
  const projectId = "test-proj";
  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-recon-cache-"));
    process.env.DEEPSEC_DATA_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-data-"));
  });
  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  function write(rel: string, content: string) {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }

  it("changes when a route file changes (cache invalidation)", () => {
    write("app/api/a/route.ts", `export async function GET() { return Response.json({}) }`);
    const f1 = computeSurfaceFingerprint(root, ["app/api/a/route.ts"]);
    write(
      "app/api/a/route.ts",
      `export async function GET() { return Response.json({ changed: 1 }) }`,
    );
    const f2 = computeSurfaceFingerprint(root, ["app/api/a/route.ts"]);
    expect(f1).not.toBe(f2);
  });

  it("caches by fingerprint and serves from cache on a second run", () => {
    write("app/api/a/route.ts", `export async function GET() { return Response.json({}) }`);
    const first = recon(projectId, root);
    expect(first.fromCache).toBe(false);
    const second = recon(projectId, root);
    expect(second.fromCache).toBe(true);
    expect(second.map.surfaceFingerprint).toBe(first.map.surfaceFingerprint);
  });

  it("re-extracts (new fingerprint) when the surface changes", () => {
    write("app/api/a/route.ts", `export async function GET() { return Response.json({}) }`);
    const first = recon(projectId, root);
    write("app/api/b/route.ts", `export async function GET() { return Response.json({}) }`);
    const second = recon(projectId, root);
    expect(second.fromCache).toBe(false);
    expect(second.map.surfaceFingerprint).not.toBe(first.map.surfaceFingerprint);
  });
});

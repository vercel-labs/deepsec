import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { liveDir, type SurfaceMap } from "@deepsec/core";
import { extractNextjsSurface } from "./nextjs.js";

/**
 * Recon orchestration: extract the attack surface, compute the project-level
 * surface fingerprint, and cache the map. The fingerprint is computed over the
 * extractor-relevant inputs (route/handler files, middleware) plus the
 * extractor name/version and the surface schema version — so an extractor
 * upgrade or a middleware change invalidates the cache rather than silently
 * driving a stale hunt. See plans/live-investigations.md (Phase: live recon).
 */

const SURFACE_SCHEMA_VERSION = 1;
const EXTRACTOR = "nextjs-app-router";
const EXTRACTOR_VERSION = "1";

function surfaceDir(projectId: string): string {
  return path.join(liveDir(projectId), "surface");
}

export function surfaceCachePath(projectId: string, fingerprint: string): string {
  return path.join(surfaceDir(projectId), `${fingerprint}.json`);
}

/** Compute the project-level surface fingerprint over extractor inputs. */
export function computeSurfaceFingerprint(root: string, inputFiles: readonly string[]): string {
  const hash = createHash("sha256");
  hash.update(EXTRACTOR);
  hash.update("\0");
  hash.update(EXTRACTOR_VERSION);
  hash.update("\0");
  hash.update(String(SURFACE_SCHEMA_VERSION));
  for (const rel of [...inputFiles].sort()) {
    hash.update("\0");
    hash.update(rel);
    try {
      hash.update("\0");
      hash.update(fs.readFileSync(path.join(root, rel)));
    } catch {
      // A file that vanished mid-scan still changes the fingerprint.
      hash.update("\0<missing>");
    }
  }
  return hash.digest("hex");
}

export interface ReconResult {
  map: SurfaceMap;
  /** Where the map was cached. */
  cachePath: string;
  /** True when served from cache rather than re-extracted. */
  fromCache: boolean;
}

/**
 * Extract (or load from cache) the surface map for a project rooted at `root`.
 * Caches by fingerprint under data/<projectId>/live/surface/.
 */
export function recon(projectId: string, root: string): ReconResult {
  const extraction = extractNextjsSurface(root);
  const fingerprint = computeSurfaceFingerprint(root, extraction.inputFiles);
  const cachePath = surfaceCachePath(projectId, fingerprint);

  if (fs.existsSync(cachePath)) {
    const cached = JSON.parse(fs.readFileSync(cachePath, "utf-8")) as SurfaceMap;
    return { map: cached, cachePath, fromCache: true };
  }

  const map: SurfaceMap = {
    version: SURFACE_SCHEMA_VERSION,
    projectId,
    surfaceFingerprint: fingerprint,
    extractor: EXTRACTOR,
    extractorVersion: EXTRACTOR_VERSION,
    generatedAt: new Date().toISOString(),
    routes: extraction.routes,
    coverage: {
      totalRouteFiles: extraction.totalRouteFiles,
      mappedRoutes: extraction.routes.length,
      unmappedFiles: extraction.unmappedFiles,
    },
  };

  fs.mkdirSync(surfaceDir(projectId), { recursive: true });
  fs.writeFileSync(cachePath, JSON.stringify(map, null, 2) + "\n");
  return { map, cachePath, fromCache: false };
}

/**
 * Load the current surface map for a project rooted at `root`, extracting (or
 * serving from cache) as needed. `live hunt` uses this so the source-defined
 * surface — not a hand-listed set of routes — drives what gets probed.
 */
export function loadSurfaceMap(projectId: string, root: string): SurfaceMap {
  return recon(projectId, root).map;
}

import { createHash } from "node:crypto";
import path from "node:path";

/** Stable per-checkout name used by both init and setup recovery paths. */
export function deterministicVercelProjectName(projectId: string, targetRoot: string): string {
  const slug =
    projectId
      .toLowerCase()
      .replace(/[^a-z0-9-]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 40) || "project";
  const suffix = createHash("sha256").update(path.resolve(targetRoot)).digest("hex").slice(0, 8);
  return `deepsec-${slug}-${suffix}`;
}

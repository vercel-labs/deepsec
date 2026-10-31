import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { deepsecDataIgnoreGlobs, IGNORE_DIRS } from "@deepsec/scanner";
import { minimatch } from "minimatch";

export function setupRepositoryIgnoreGlobs(root: string, workspaceDir?: string): string[] {
  const absoluteRoot = path.resolve(root);
  const ignores = [...deepsecDataIgnoreGlobs(absoluteRoot)];
  if (workspaceDir) {
    const relative = path
      .relative(absoluteRoot, path.resolve(workspaceDir))
      .split(path.sep)
      .join("/");
    if (relative && relative !== "." && !relative.startsWith("../") && !path.isAbsolute(relative)) {
      ignores.push(`${relative}/**`);
    }
  }
  return [...new Set(ignores)];
}

export function listRepositoryFiles(
  root: string,
  additionalIgnores: readonly string[] = [],
): string[] {
  const absoluteRoot = path.resolve(root);
  const ignores = [...IGNORE_DIRS, ...deepsecDataIgnoreGlobs(absoluteRoot), ...additionalIgnores];
  const files: string[] = [];
  const visit = (dir: string) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const absolute = path.join(dir, entry.name);
      const relative = path.relative(absoluteRoot, absolute).split(path.sep).join("/");
      const ignored = ignores.some(
        (glob) =>
          minimatch(relative, glob, { dot: true }) ||
          (entry.isDirectory() && minimatch(`${relative}/__deepsec_entry__`, glob, { dot: true })),
      );
      if (ignored) continue;
      if (entry.isDirectory()) visit(absolute);
      else if (entry.isFile()) files.push(relative);
    }
  };
  visit(absoluteRoot);
  return files.sort();
}

/** Cheap, content-sensitive fingerprint used to invalidate setup checkpoints. */
export function repositoryFingerprint(root: string, files = listRepositoryFiles(root)): string {
  const hash = createHash("sha256");
  for (const relative of files) {
    const absolute = path.join(root, relative);
    const stat = fs.statSync(absolute);
    hash.update(relative).update("\0").update(String(stat.size)).update("\0");
    hash.update(fs.readFileSync(absolute)).update("\0");
  }
  return hash.digest("hex");
}

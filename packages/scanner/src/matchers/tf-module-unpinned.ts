import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * `module "x" { source = "..." }` referencing a remote git/github source
 * without a `?ref=<sha>` pin → mutable upstream, supply-chain risk.
 *
 * Acceptable: local sources (`./` / `../`), Terraform Registry sources
 * `(<ns>/<name>/<provider>` with a `version =`), or git URLs with a
 * commit-SHA `?ref=`.
 */
export const tfModuleUnpinnedMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "tf-module-unpinned",
  description: "Terraform module references a remote git/github source without a commit-SHA pin",
  filePatterns: ["**/*.tf"],
  requires: { tech: ["terraform"] },
  examples: [
    `module "vpc" {\n  source = "github.com/terraform-aws-modules/terraform-aws-vpc"\n}`,
    `module "k8s" {\n  source = "git::https://github.com/some-org/k8s-module.git"\n}`,
    `module "iam" {\n  source = "git::ssh://git@github.com/org/iam.git?ref=main"\n}`,
    `module "registry" {\n  source = "terraform-aws-modules/eks/aws"\n}`,
    `module "external" {\n  source = "https://example.com/modules/foo.tar.gz"\n}`,
  ],
  match(content) {
    const lines = content.split("\n");
    const hitLines: number[] = [];
    const labels = new Set<string>();
    let firstContext: string | undefined;

    // Track module blocks across lines
    let inModule = false;
    let moduleStart = -1;
    let moduleSource = "";
    let moduleHasVersion = false;
    let depth = 0;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!inModule && /^\s*module\s+"[^"]+"\s*\{/.test(line)) {
        inModule = true;
        moduleStart = i;
        moduleSource = "";
        moduleHasVersion = false;
        depth = 1;
        continue;
      }
      if (!inModule) continue;
      for (const ch of line) {
        if (ch === "{") depth++;
        else if (ch === "}") depth--;
      }
      const sm = line.match(/^\s*source\s*=\s*"([^"]+)"/);
      if (sm) moduleSource = sm[1];
      if (/^\s*version\s*=\s*"[^"]+"/.test(line)) moduleHasVersion = true;
      if (depth <= 0) {
        // module block closed — evaluate
        const src = moduleSource;
        const local = src.startsWith("./") || src.startsWith("../") || src.startsWith("/");
        const looksRemote =
          /^(?:git::|github\.com\/|bitbucket\.org\/|https?:\/\/)/i.test(src) ||
          /^[\w.-]+@/.test(src);
        const looksRegistry =
          /^[a-z0-9-]+\/[a-z0-9-]+\/[a-z0-9-]+(?:\/\/[\w/-]+)?$/i.test(src) &&
          !src.startsWith("git::");
        const isPinned = /\?ref=[0-9a-f]{7,40}\b/.test(src) || /(\?|&)tag=[\w.-]+/.test(src);
        const okPinned = local || (looksRegistry && moduleHasVersion) || (looksRemote && isPinned);
        if (!okPinned && (looksRemote || (looksRegistry && !moduleHasVersion))) {
          hitLines.push(moduleStart + 1);
          labels.add(local ? "local" : looksRegistry ? "registry no version" : "remote unpinned");
          if (firstContext === undefined) {
            const s = Math.max(0, moduleStart);
            const e = Math.min(lines.length, i + 2);
            firstContext = lines.slice(s, e).join("\n");
          }
        }
        inModule = false;
        moduleStart = -1;
      }
    }

    if (hitLines.length === 0) return [];
    const match: CandidateMatch = {
      vulnSlug: "tf-module-unpinned",
      lineNumbers: hitLines,
      snippet: firstContext ?? "",
      matchedPattern: Array.from(labels).slice(0, 3).join(", "),
    };
    return [match];
  },
};

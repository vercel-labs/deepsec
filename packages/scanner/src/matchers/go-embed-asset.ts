import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Go `//go:embed` directives that bundle external assets into a binary —
 * particularly executable / kernel / rootfs payloads. These are part of the
 * supply chain: an attacker who can replace the embedded asset at build
 * time gets a copy of their bytes shipping in production.
 *
 * Flags every `//go:embed` line; the AI pass should verify the asset is
 * checked into the repo, the file path is not glob-too-wide, and the
 * embed isn't pulling secrets or runtime-mutable data.
 */
export const goEmbedAssetMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "go-embed-asset",
  description: "Go //go:embed directive (binary assets bundled into the program)",
  filePatterns: ["**/*.go"],
  requires: { tech: ["go"] },
  examples: [
    `//go:embed kernel.bin\nvar kernelImage []byte`,
    `//go:embed rootfs.tar.gz\nvar rootfs []byte`,
    `//go:embed assets/*\nvar assets embed.FS`,
    `//go:embed templates/index.html\nvar indexHTML []byte`,
    `//go:embed config.yaml\nvar configBytes []byte`,
  ],
  match(content, filePath) {
    if (/_test\.go$/.test(filePath)) return [];
    if (/(?:^|\/)gen\//.test(filePath)) return [];

    const lines = content.split("\n");
    const hitLines: number[] = [];
    const labels = new Set<string>();
    let firstContext: string | undefined;

    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(/^\s*\/\/go:embed\s+(.+?)\s*$/);
      if (!m) continue;
      hitLines.push(i + 1);
      labels.add(m[1].slice(0, 60));
      if (firstContext === undefined) {
        const s = Math.max(0, i - 2);
        const e = Math.min(lines.length, i + 4);
        firstContext = lines.slice(s, e).join("\n");
      }
    }

    if (hitLines.length === 0) return [];
    const match: CandidateMatch = {
      vulnSlug: "go-embed-asset",
      lineNumbers: hitLines,
      snippet: firstContext ?? "",
      matchedPattern: Array.from(labels).slice(0, 3).join(" | "),
    };
    return [match];
  },
};

import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Classic supply-chain pattern: `curl … | sh` / `curl … | tar -x` in a
 * Dockerfile RUN, without a checksum-verification step (sha256sum, shasum,
 * gpg --verify) in the same RUN block. The build executes arbitrary code or
 * extracts files downloaded from an external host with no integrity check.
 */
export const dockerfileCurlPipeUnverifiedMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "dockerfile-curl-pipe-unverified",
  description: "RUN curl|wget piped to shell/tar without checksum verification",
  filePatterns: ["**/Dockerfile", "**/Dockerfile.*", "**/*.Dockerfile"],
  requires: { tech: ["docker"] },
  examples: [
    `RUN curl -fsSL https://example.com/install.sh | sh`,
    `RUN curl -L https://get.docker.com/ | bash`,
    `RUN wget -qO- https://example.com/install | sh`,
    `RUN curl -L https://example.com/release.tar.gz | tar -xz`,
    `RUN wget -O- https://example.com/file.zip | unzip -`,
  ],
  match(content) {
    const lines = content.split("\n");
    const hitLines: number[] = [];
    const snippets: string[] = [];

    // Coalesce RUN ... \ continuation lines into logical statements.
    const statements: { start: number; text: string }[] = [];
    let i = 0;
    while (i < lines.length) {
      const line = lines[i];
      if (!/^\s*RUN\b/i.test(line)) {
        i++;
        continue;
      }
      const start = i;
      let text = line;
      while (text.trimEnd().endsWith("\\") && i + 1 < lines.length) {
        i++;
        text += "\n" + lines[i];
      }
      statements.push({ start, text });
      i++;
    }

    const PIPE = /\b(curl|wget)\b[^|\n]*\|\s*(?:sh|bash|zsh|tar\b|gunzip\b|unzip\b)/i;
    const HAS_VERIFY =
      /(sha256sum|sha1sum|shasum|gpg\s+--?verify|cosign\s+verify|minisign|openssl\s+dgst)/i;

    for (const stmt of statements) {
      if (!PIPE.test(stmt.text)) continue;
      if (HAS_VERIFY.test(stmt.text)) continue;
      hitLines.push(stmt.start + 1);
      const snipStart = Math.max(0, stmt.start - 1);
      const snipEnd = Math.min(lines.length, stmt.start + stmt.text.split("\n").length + 1);
      snippets.push(lines.slice(snipStart, snipEnd).join("\n"));
    }

    if (hitLines.length === 0) return [];
    const match: CandidateMatch = {
      vulnSlug: "dockerfile-curl-pipe-unverified",
      lineNumbers: hitLines,
      snippet: snippets[0],
      matchedPattern: "curl|wget | sh/tar with no checksum check",
    };
    return [match];
  },
};

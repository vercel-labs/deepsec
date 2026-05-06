import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Entry-point matcher for the Next.js image optimizer and its private-IP
 * defenses. Historically the highest-impact CVE class in Next.js (SSRF
 * to internal services / cloud metadata endpoints).
 *
 * Files flagged:
 *   - `image-optimizer.ts`, `image-blur-svg.ts`
 *   - `is-private-ip.ts` (the private-IP allow-list / reject helper)
 *   - `image-config.ts`, `image-config-context.shared-runtime.ts`
 *   - `match-remote-pattern.ts`, `match-host.ts`
 *
 * Plus any file that calls `imageOptimizer(...)` or imports from
 * `next/image-optimizer`.
 */
export const frameworkImageOptimizerMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "framework-image-optimizer",
  description: "Next.js image-optimizer and private-IP allow-list code (SSRF risk surface)",
  filePatterns: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.mjs"],
  requires: { tech: ["nextjs"] },
  examples: [
    `await imageOptimizer({ req, res, parsedUrl, nextConfig });`,
    `const buf = await optimizeImage(input, { width });`,
    `const remotePatterns = config.images.remotePatterns;`,
    `if (config.domains.includes(host)) return true;`,
    `const loaderFile = require(config.images.loaderFile);`,
    `if (isPrivateIP(addr)) throw new Error('blocked');`,
    `const m = host.match(IP_ADDRESS_REGEX);`,
    `if (matchRemotePattern(p, parsed)) return true;`,
    `if (matchHost(p.hostname, parsed.hostname)) return true;`,
    `if (host === '169.254.169.254') throw new Error('metadata blocked');`,
    `if (ip === '127.0.0.1' || ip === '0.0.0.0') return false;`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)$/.test(filePath)) return [];
    if (/\.d\.ts$/.test(filePath)) return [];

    const PATH_HINT =
      /(?:^|\/)(?:image-optimizer|image-blur-svg|is-private-ip|match-remote-pattern|match-host|image-config|image-config-context\.shared-runtime|image-content-disposition|require-fonts|next-image-loader)\.[tj]sx?$/;
    const CONTENT_HINTS = [
      /\bimageOptimizer\s*\(|\boptimizeImage\s*\(/,
      /\b(?:remotePatterns|domains|loaderFile)\b/,
      /\bisPrivateIP\s*\(|\bIP_ADDRESS_REGEX\b/,
      /\bmatchRemotePattern\s*\(|\bmatchHost\s*\(/,
      /\b(?:169\.254\.169\.254|0\.0\.0\.0|127\.0\.0\.1|::1|::ffff:)/,
    ];

    const isByPath = PATH_HINT.test(filePath);
    const lines = content.split("\n");
    const hitLines: number[] = [];
    const labels = new Set<string>();
    let firstContext: string | undefined;

    for (let i = 0; i < lines.length; i++) {
      for (const re of CONTENT_HINTS) {
        if (re.test(lines[i])) {
          hitLines.push(i + 1);
          labels.add(re.source.slice(0, 40));
          if (firstContext === undefined) {
            const s = Math.max(0, i - 2);
            const e = Math.min(lines.length, i + 3);
            firstContext = lines.slice(s, e).join("\n");
          }
          break;
        }
      }
    }

    if (hitLines.length === 0 && isByPath) {
      const match: CandidateMatch = {
        vulnSlug: "framework-image-optimizer",
        lineNumbers: [1],
        snippet: lines.slice(0, 5).join("\n"),
        matchedPattern: "image optimizer file (path)",
      };
      return [match];
    }
    if (hitLines.length === 0) return [];
    const match: CandidateMatch = {
      vulnSlug: "framework-image-optimizer",
      lineNumbers: hitLines,
      snippet: firstContext ?? "",
      matchedPattern: Array.from(labels).slice(0, 3).join(", "),
    };
    return [match];
  },
};

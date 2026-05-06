import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Front repo: More nuanced XSS detection for React/Next.js apps.
 * Classifies dangerouslySetInnerHTML by whether the source is user-controlled.
 */
export const dangerousHtmlMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "dangerous-html",
  description: "dangerouslySetInnerHTML and innerHTML with source classification",
  filePatterns: ["**/*.{tsx,jsx,ts,js}"],
  examples: [
    `<div dangerouslySetInnerHTML={{ __html: html }} />`,
    `<span dangerouslySetInnerHTML={{ __html: props.body }} />`,
    `el.innerHTML = data;`,
    `node.innerHTML = result;`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      if (/dangerouslySetInnerHTML/.test(line) || /\.innerHTML\s*=/.test(line)) {
        const start = Math.max(0, i - 3);
        const end = Math.min(lines.length, i + 5);
        const context = lines.slice(start, end).join("\n");

        // Classify the source
        const isSafeScript = /\.toString\(\)/.test(context) || /IIFE|function\s*\(/.test(context);
        const isStaticString = /dangerouslySetInnerHTML.*__html:\s*['"`]/.test(context);
        const isFromProps = /props\.|children|content|html|body|text|message/i.test(context);
        const isFromFetch = /data\.|response\.|result\.|await|fetch/i.test(context);
        const isFromSearchParams = /searchParams|query|params|req\./i.test(context);

        let label: string;
        if (isFromSearchParams) {
          label = "dangerouslySetInnerHTML from URL/request params (HIGH RISK)";
        } else if (isFromFetch) {
          label = "dangerouslySetInnerHTML from fetched data (MEDIUM RISK)";
        } else if (isFromProps) {
          label = "dangerouslySetInnerHTML from props (trace source)";
        } else if (isSafeScript || isStaticString) {
          label = "dangerouslySetInnerHTML with static/safe content (weak candidate)";
        } else {
          label = "dangerouslySetInnerHTML (classify source)";
        }

        matches.push({
          vulnSlug: "dangerous-html",
          lineNumbers: [i + 1],
          snippet: lines.slice(start, end).join("\n"),
          matchedPattern: label,
        });
      }
    }

    return matches;
  },
};

import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

export const urlRegexValidationMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "url-regex-validation",
  description: "Regex-based URL/hostname validation with .+ or .* patterns — bypassable",
  filePatterns: ["**/*.{ts,tsx,js,jsx}"],
  examples: [
    `const re = new RegExp("https?://.+\\\\.example\\\\.com");
if (re.test(url)) ok();`,
    `if (/^https?:\\/\\/.+\\.trusted\\.com/.test(url)) ok();`,
    `const ok = /https?:.+\\.example\\.com/.test(url);`,
    `const re = /https?:.*\\.foo\\.com/;
if (re.test(url)) good();`,
    `const u = new URL(req.query.target);`,
    `const u = new URL(params.url);`,
    `const u = new URL(body.callbackUrl);`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Regex literal or RegExp constructor with URL pattern + greedy wildcard
      const hasUrlRegex =
        (/https?.*\.\+|https?.*\.\*/.test(line) && /RegExp|\/.*\/|\.test|\.match/.test(line)) ||
        /new RegExp\s*\(.*https?/.test(line) ||
        // Regex literal with URL + .+
        /\/\^?https?:.*\.\+.*\//.test(line);

      // new URL() without hostname check
      const hasUncheckedUrl =
        /new\s+URL\s*\(/.test(line) &&
        !/\.hostname\s*===|\.host\s*===/.test(
          lines.slice(i, Math.min(lines.length, i + 5)).join("\n"),
        );

      if (hasUrlRegex) {
        const start = Math.max(0, i - 1);
        const end = Math.min(lines.length, i + 3);
        matches.push({
          vulnSlug: "url-regex-validation",
          lineNumbers: [i + 1],
          snippet: lines.slice(start, end).join("\n"),
          matchedPattern:
            "URL validation regex with greedy wildcard (.+ or .*) — may be bypassable",
        });
      } else if (hasUncheckedUrl && /req\.|params\.|query\.|body\.|parsed\./.test(line)) {
        const start = Math.max(0, i - 1);
        const end = Math.min(lines.length, i + 3);
        matches.push({
          vulnSlug: "url-regex-validation",
          lineNumbers: [i + 1],
          snippet: lines.slice(start, end).join("\n"),
          matchedPattern: "new URL() from request input without hostname validation",
        });
      }
    }

    return matches;
  },
};

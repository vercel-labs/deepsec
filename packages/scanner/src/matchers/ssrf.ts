import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const ssrfMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "ssrf",
  description: "HTTP requests with dynamic/user-controlled URLs",
  filePatterns: ["**/*.{ts,tsx,js,jsx}"],
  examples: [
    `fetch(req.body.url);`,
    `fetch(query.target);`,
    `axios.get(req.body.endpoint);`,
    `axios.post(params.url, data);`,
    "https.request(`https://api/${req.body.host}`);",
    `new URL(req.query.target);`,
    "fetch(`${userBase}/items`);",
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    const matches = regexMatcher(
      "ssrf",
      [
        {
          regex: /fetch\s*\(\s*(req\.|request\.|params\.|query\.|body\.|parsed\.)/,
          label: "fetch with request-derived URL",
        },
        {
          regex:
            /axios\.(get|post|put|delete|patch|request)\s*\(\s*(req\.|request\.|params\.|query\.|body\.)/,
          label: "axios with request-derived URL",
        },
        { regex: /https?\.request\s*\(\s*`[^`]*\$\{/, label: "http.request with interpolated URL" },
        {
          regex: /new\s+URL\s*\(\s*(req\.|request\.|params\.|query\.|body\.)/,
          label: "new URL from request data",
        },
      ],
      content,
    );

    // For fetch with template literals, only flag if not using a constant base URL
    const lines = content.split("\n");
    const constantBaseUrls = /VERCEL_API_URL|API_BASE|API_URL|INTERNAL_URL|process\.env\.\w+_URL/;
    for (let i = 0; i < lines.length; i++) {
      if (/fetch\s*\(\s*`[^`]*\$\{/.test(lines[i]) && !constantBaseUrls.test(lines[i])) {
        const start = Math.max(0, i - 2);
        const end = Math.min(lines.length, i + 3);
        matches.push({
          vulnSlug: "ssrf",
          lineNumbers: [i + 1],
          snippet: lines.slice(start, end).join("\n"),
          matchedPattern: "fetch with interpolated URL (non-constant base)",
        });
      }
    }

    return matches;
  },
};

import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

export const unsafeJsonInHtmlMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "unsafe-json-in-html",
  description:
    "JSON.stringify into dangerouslySetInnerHTML or script tags — </script> injection risk",
  filePatterns: ["**/*.{tsx,jsx,ts,js}"],
  requires: { tech: ["react"] },
  examples: [
    `<div dangerouslySetInnerHTML={{ __html: JSON.stringify(data) }} />`,
    `return <script dangerouslySetInnerHTML={{ __html: 'window.__DATA__ = ' + JSON.stringify(state) }} />`,
    `const html = '<script>window.X = ' + JSON.stringify(payload) + '</script>'`,
    `return (\n  <script>\n    {'window.STATE = ' + JSON.stringify(state)}\n  </script>\n)`,
    `const json = JSON.stringify(props);\nreturn <div dangerouslySetInnerHTML={{ __html: json }} />`,
    `import { safeJsonStringify } from './util';\nconst payload = JSON.stringify(state);\nreturn <script dangerouslySetInnerHTML={{ __html: 'window.X = ' + payload }} />`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    // Skip if using safeJsonStringify
    const usesSafe = /safeJsonStringify/.test(content);

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // JSON.stringify near dangerouslySetInnerHTML
      const hasJsonStringify = /JSON\.stringify/.test(line);
      const hasDangerousHtml = /dangerouslySetInnerHTML/.test(line);

      // Check surrounding context (5 lines)
      const context = lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 3)).join("\n");
      const contextHasJson = /JSON\.stringify/.test(context);
      const contextHasDangerous = /dangerouslySetInnerHTML/.test(context);
      const contextHasScript = /<script/.test(context);

      if (hasJsonStringify && (contextHasDangerous || contextHasScript)) {
        const start = Math.max(0, i - 2);
        const end = Math.min(lines.length, i + 3);
        matches.push({
          vulnSlug: "unsafe-json-in-html",
          lineNumbers: [i + 1],
          snippet: lines.slice(start, end).join("\n"),
          matchedPattern: usesSafe
            ? "JSON.stringify near HTML injection point (safeJsonStringify in scope — verify usage)"
            : "JSON.stringify into dangerouslySetInnerHTML/script — use safeJsonStringify to escape </script>",
        });
      } else if (hasDangerousHtml && contextHasJson) {
        const start = Math.max(0, i - 2);
        const end = Math.min(lines.length, i + 3);
        matches.push({
          vulnSlug: "unsafe-json-in-html",
          lineNumbers: [i + 1],
          snippet: lines.slice(start, end).join("\n"),
          matchedPattern: usesSafe
            ? "dangerouslySetInnerHTML with JSON data (safeJsonStringify in scope)"
            : "dangerouslySetInnerHTML with JSON.stringify — XSS via </script> in data",
        });
      }
    }

    return matches;
  },
};

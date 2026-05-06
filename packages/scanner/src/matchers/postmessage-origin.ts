import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

export const postmessageOriginMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "postmessage-origin",
  description: "postMessage handlers without origin validation — XSS via malicious parent frame",
  filePatterns: ["**/*.{ts,tsx,js,jsx}"],
  examples: [
    `window.addEventListener("message", (event) => {
  document.body.innerHTML = event.data;
});`,
    `window.addEventListener('message', handleMsg);`,
    `iframe.onmessage = (e) => {
  console.log(e.data);
};`,
    `frame.onmessage = function (e) { dispatch(e.data); };`,
    `addEventListener("message", function (event) {
  if (event.origin !== "https://trusted.example") return;
  doStuff(event.data);
});`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];
    if (!/addEventListener.*message|onmessage/.test(content)) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      if (
        /addEventListener\s*\(\s*['"]message['"]/.test(lines[i]) ||
        /\.onmessage\s*=/.test(lines[i])
      ) {
        // Check the next 10 lines for origin validation
        const window = lines.slice(i, Math.min(lines.length, i + 10)).join("\n");
        const hasOriginCheck =
          /event\.origin|\.origin\s*[!=]==?|origin.*check|validat.*origin/.test(window);

        const start = Math.max(0, i - 1);
        const end = Math.min(lines.length, i + 5);
        matches.push({
          vulnSlug: "postmessage-origin",
          lineNumbers: [i + 1],
          snippet: lines.slice(start, end).join("\n"),
          matchedPattern: hasOriginCheck
            ? "postMessage handler with origin check (verify strictness)"
            : "postMessage handler WITHOUT origin validation",
        });
      }
    }

    return matches;
  },
};

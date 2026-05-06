import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Server-side fetch following redirects across hosts. Common SSRF bypass:
 *   - Host validation runs against the request URL ("https://allowed.com/...")
 *   - The fetch follows a 30x to "https://169.254.169.254/...", "http://localhost:8080/..."
 *   - Now you've reached cloud metadata or internal services
 *
 * Default Fetch API behavior is `redirect: 'follow'`. To be safe a
 * server-side fetch of a caller-influenced URL must EITHER:
 *   - Set `redirect: 'manual'` and re-validate the resolved Location, OR
 *   - Use a fetch wrapper that re-validates per-hop, OR
 *   - Block fetches to private IP ranges entirely (DNS resolution check)
 *
 * Flags `fetch(url)` / `axios.get(url)` / `got(url)` calls in server-side
 * files where the URL likely derives from caller input. Also flags
 * explicit `redirect: 'follow'` and absence of `redirect:` setting in
 * suspicious contexts.
 */
export const untrustedRedirectFollowingMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "untrusted-redirect-following",
  description: "Server-side fetch follows redirects — SSRF bypass risk if URL is caller-influenced",
  filePatterns: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.mjs"],
  examples: [
    `await fetch(targetUrl, { redirect: "follow" });`,
    `await fetch(callbackUrl);`,
    `const res = await fetch(redirectUrl);`,
    `const r = await fetch(webhookUrl);`,
    `await axios.get(companyUrl);`,
    `await axios.post(websiteUrl, payload);`,
    `await got(domainUrl);`,
    `await got(imageUrl);
got.get(imageUrl);`,
    `await fetch(fetchUrl, { method: "GET" });`,
    `await fetch(returnTo, { method: "GET" });`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)$/.test(filePath)) return [];
    if (/\.d\.ts$/.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];
    // Skip clearly client-side files
    if (/\.client\.(ts|tsx|js|mjs)$/.test(filePath)) return [];

    const HAS_OUTBOUND = /\bfetch\s*\(|\baxios\b|\bgot\s*\(|\bundici\b|\bnode-fetch\b|\bphin\b/;
    if (!HAS_OUTBOUND.test(content)) return [];

    // Variable-name hints suggesting URL came from caller / data
    const URL_VAR =
      /\b(?:url|targetUrl|callbackUrl|redirectUrl|webhookUrl|companyUrl|websiteUrl|domainUrl|imageUrl|fetchUrl|next|return_to|returnTo|destination|location)\b/;

    const lines = content.split("\n");
    const matches: CandidateMatch[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      if (/\bredirect\s*:\s*["']follow["']/.test(line)) {
        const start = Math.max(0, i - 2);
        const end = Math.min(lines.length, i + 3);
        matches.push({
          vulnSlug: "untrusted-redirect-following",
          lineNumbers: [i + 1],
          snippet: lines.slice(start, end).join("\n"),
          matchedPattern: "explicit redirect: 'follow' — verify URL is allowlisted",
        });
        continue;
      }

      // fetch(url) call where `url` is a caller-style variable
      const m = line.match(
        /\b(?:fetch|axios\.\s*(?:get|post|put|delete|head)|got|got\.\s*(?:get|post))\s*\(\s*([^,)]+)/,
      );
      if (m && URL_VAR.test(m[1])) {
        // Skip if the same call sets redirect: 'manual' or 'error' on a
        // following line within the next 4
        const window = lines.slice(i, Math.min(lines.length, i + 5)).join("\n");
        if (/\bredirect\s*:\s*["'](?:manual|error)["']/.test(window)) continue;

        const start = Math.max(0, i - 1);
        const end = Math.min(lines.length, i + 3);
        matches.push({
          vulnSlug: "untrusted-redirect-following",
          lineNumbers: [i + 1],
          snippet: lines.slice(start, end).join("\n"),
          matchedPattern: `fetch(${m[1].slice(0, 40).trim()}) — default redirect: follow + caller-style URL`,
        });
      }
    }
    return matches;
  },
};

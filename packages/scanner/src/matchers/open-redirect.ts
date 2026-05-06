import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const openRedirectMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "open-redirect",
  description: "Redirects with user-controlled URLs",
  filePatterns: ["**/*.{ts,tsx,js,jsx}"],
  examples: [
    `redirect(req.body.next);`,
    `redirect(query.target);`,
    "redirect(`${origin}/${req.body.path}`);",
    `res.redirect(req.body.url);`,
    `res.redirect(params.next);`,
    `headers: { Location: req.body.next }`,
    `window.location = params.next;`,
    `const u = returnUrl;`,
    `const r = redirectUrl;`,
    `const x = returnTo;`,
  ],
  match(content, _filePath) {
    return regexMatcher(
      "open-redirect",
      [
        {
          regex: /redirect\s*\(\s*(req\.|request\.|params\.|query\.|body\.)/,
          label: "redirect with request-derived URL",
        },
        { regex: /redirect\s*\(\s*`[^`]*\$\{/, label: "redirect with interpolated URL" },
        {
          regex: /res\.redirect\s*\(\s*(req\.|request\.|params\.|query\.|body\.)/,
          label: "res.redirect with request-derived URL",
        },
        {
          regex: /Location.*:\s*(req\.|request\.|params\.|query\.|body\.)/,
          label: "Location header from request data",
        },
        {
          regex: /window\.location\s*=\s*(req|params|query|searchParams)/,
          label: "window.location from user input",
        },
        { regex: /returnUrl|redirectUrl|returnTo|next.*url/i, label: "redirect URL parameter" },
      ],
      content,
    );
  },
};

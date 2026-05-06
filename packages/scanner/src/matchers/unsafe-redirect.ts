import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Front repo: Finds redirects that may not use validNextRedirect().
 * The front repo has a proper redirect validation function — flag any
 * redirect that doesn't use it.
 */
export const unsafeRedirectMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "unsafe-redirect",
  description: "Redirects that may bypass validNextRedirect() — open redirect risk",
  filePatterns: ["**/*.{ts,tsx,js,jsx}"],
  examples: [
    `redirect(req.body.next);`,
    `redirect(query.target);`,
    `redirect(searchParams.get("u"));`,
    `redirect(params.next);`,
    "redirect(`/${req.body.path}`);",
    `NextResponse.redirect(new URL(target, base));`,
    `// x-app-redirect-uri header\nredirect(target);`,
    `// returnUrl from query\nredirect(target);`,
    `// returnTo param\nredirect(t);`,
    `// redirectUrl from body\nredirect(t);`,
    `// redirect.uri from header\nredirect(t);`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    // Check if file uses redirect patterns
    const hasRedirect =
      /redirect\s*\(|NextResponse\.redirect|router\.push|router\.replace|window\.location/i.test(
        content,
      );
    if (!hasRedirect) return [];

    // Check if file imports/uses validNextRedirect
    const hasValidation = /validNextRedirect/.test(content);

    const patterns: { regex: RegExp; label: string }[] = [
      {
        regex: /redirect\s*\(\s*(req\.|request\.|params\.|query\.|searchParams|body\.)/,
        label: "redirect() with request-derived URL",
      },
      {
        regex: /redirect\s*\(\s*`[^`]*\$\{/,
        label: "redirect() with interpolated URL",
      },
      {
        regex: /NextResponse\.redirect\s*\(\s*new\s+URL\s*\(/,
        label: "NextResponse.redirect with dynamic URL",
      },
      {
        regex: /x-app-redirect-uri|redirect.uri|redirectUrl|returnUrl|returnTo/i,
        label: "Redirect URL from header/param",
      },
    ];

    for (const { regex, label } of patterns) {
      for (let i = 0; i < lines.length; i++) {
        if (regex.test(lines[i])) {
          const start = Math.max(0, i - 2);
          const end = Math.min(lines.length, i + 3);
          matches.push({
            vulnSlug: "unsafe-redirect",
            lineNumbers: [i + 1],
            snippet: lines.slice(start, end).join("\n"),
            matchedPattern: hasValidation
              ? `${label} (validNextRedirect in scope — verify usage)`
              : `${label} (NO validNextRedirect — investigate)`,
          });
        }
      }
    }

    return matches;
  },
};

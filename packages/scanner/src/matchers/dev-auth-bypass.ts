import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Development/test authentication bypasses that may be reachable in production.
 * These include dev-only auth endpoints, NODE_ENV guards around auth, and
 * test token acceptance.
 */
export const devAuthBypassMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "dev-auth-bypass",
  description:
    "Development auth bypasses — dev endpoints, NODE_ENV guards, test tokens in production",
  filePatterns: ["**/*.{ts,tsx,js,jsx}"],
  examples: [
    `app.post("/auth/dev", (req, res) => {
  res.json({ token: "dev-token" });
});`,
    `router.get("/dev/login", handler);`,
    `app.post("/test/auth/login", handler);`,
    `if (NODE_ENV === "development") return skipAuthMiddleware();`,
    `if (NODE_ENV === "test") return mockAuthResponse();`,
    `function shouldBypassAuth() { return skipAuthHandler() && NODE_ENV; }`,
    `if (isDev) {
  ctx.user = { id: 1, role: "admin" };
}`,
    `if (IS_TEST) return adminUser;`,
    `const token = headers.get("test-token") || "";`,
    `if (apiKey === "test_api_key_12345") return ok();`,
    `const session = createMockSession({ userId: 1 });`,
    `await autoLogin(req);`,
    `useFakeAuth(req);`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    const patterns: { regex: RegExp; label: string }[] = [
      // Dev auth endpoints
      {
        regex: /\/auth\/dev|\/api\/dev|\/dev\/login|\/test\/auth/,
        label: "Dev/test auth endpoint — may be reachable in production",
      },
      // NODE_ENV guards around auth
      {
        regex:
          /NODE_ENV.{0,40}(?:development|test).{0,80}(?:skip|bypass|disable|return|mock).{0,40}auth/i,
        label: "Auth skipped in development/test — check production guard",
      },
      {
        regex: /(?:skip|bypass|disable|mock).{0,40}auth.{0,80}NODE_ENV/i,
        label: "Auth bypass gated by NODE_ENV — check production guard",
      },
      // Explicit dev bypasses
      {
        regex: /if\s*\(\s*(?:!?\s*)?(?:isDev|isTest|isLocal|IS_DEV|IS_TEST)/,
        label: "Auth conditional on isDev/isTest flag — fails open risk",
      },
      // Test tokens accepted
      {
        regex: /test[_-]?(?:token|bearer|api[_-]?key|secret)/i,
        label: "Test token/secret reference — may be accepted in production",
      },
      // Auto-login / mock session
      {
        regex: /mock[_-]?(?:session|user|auth)|auto[_-]?login|fake[_-]?auth/i,
        label: "Mock session/auth pattern — check production guard",
      },
    ];

    for (const { regex, label } of patterns) {
      for (let i = 0; i < lines.length; i++) {
        if (regex.test(lines[i])) {
          // Skip comment-only lines
          const trimmed = lines[i].trim();
          if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;

          const start = Math.max(0, i - 2);
          const end = Math.min(lines.length, i + 3);
          matches.push({
            vulnSlug: "dev-auth-bypass",
            lineNumbers: [i + 1],
            snippet: lines.slice(start, end).join("\n"),
            matchedPattern: label,
          });
        }
      }
    }

    return matches;
  },
};

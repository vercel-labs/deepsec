import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const authBypassMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "auth-bypass",
  description: "Auth checks, middleware guards, session validation that may be bypassable",
  filePatterns: ["**/*.{ts,tsx,js,jsx}"],
  examples: [
    `if (isAdmin === true) { grant(); }`,
    `user.isAdmin == req.body.isAdmin`,
    `// skip auth in development`,
    `const bypassAuth = true;`,
    `if (!session) return null;`,
    `if ( session ) { /* ok */ }`,
    `await verifyToken(token);`,
    `const ok = verifyJWT(t);`,
    `verifySession(req);`,
    `verifyAuth(headers);`,
    `app.use(authMiddleware);`,
    `const middlewareAuth = compose(...);`,
    `const t = req.headers["authorization"];`,
    `req.headers['authorization']`,
  ],
  match(content, _filePath) {
    return regexMatcher(
      "auth-bypass",
      [
        { regex: /isAdmin\s*[=!]==?\s*(true|false|req\.)/, label: "admin check comparison" },
        {
          regex: /auth.{0,30}skip|skip.{0,30}auth|bypass.{0,30}auth/i,
          label: "auth skip/bypass",
        },
        { regex: /if\s*\(\s*!?\s*session\s*\)/, label: "session null check" },
        { regex: /verify(Token|JWT|Session|Auth)\s*\(/, label: "auth verification call" },
        { regex: /middleware.{0,30}auth|auth.{0,30}middleware/i, label: "auth middleware" },
        { regex: /req\.headers\[['"]authorization['"]\]/, label: "authorization header access" },
      ],
      content,
    );
  },
};

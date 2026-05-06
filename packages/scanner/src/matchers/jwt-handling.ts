import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

/**
 * Both repos: JWT creation, signing, verification, and cookie handling.
 * Misconfigurations can lead to auth bypass or token forgery.
 */
export const jwtHandlingMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "jwt-handling",
  description: "JWT signing, verification, and cookie-based session handling",
  filePatterns: ["**/*.{ts,tsx,js,jsx}"],
  examples: [
    `import { jwtVerify } from "jose"; await jwtVerify(token, key);`,
    `import jwt from "jsonwebtoken"; jwt.verify(token, key);`,
    `await verifyJwt(token); // jwt`,
    `import { SignJWT } from "jose"; new SignJWT({}).sign(key);`,
    `import jwt from "jsonwebtoken"; jwt.sign(payload, key);`,
    `const j = jwtSign(payload); // jwt`,
    `const j = createBypassJwt(uid); // jwt`,
    `import { jwtDecrypt } from "jose"; await jwtDecrypt(token, key);`,
    `import { EncryptJWT } from "jose"; new EncryptJWT({}).encrypt(key);`,
    `const opts = { cookie: { secret: "x" } }; // jwt`,
    `const c = SESSION_COOKIE; // jwt`,
    `const c = USER_CACHE_COOKIE; // jwt`,
    `await refreshToken(); // jwt`,
    `force_refresh_access_token(); // jwt`,
    `const t = jwt.sign(p, k, { algorithm: "none" });`,
    `const t = jwt.sign(p, k, { alg: "none" });`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    // Only match files that deal with JWT/tokens
    if (!/jwt|jose|jsonwebtoken|token|session[\w\s]{0,20}cookie/i.test(content)) return [];

    return regexMatcher(
      "jwt-handling",
      [
        {
          regex: /jwtVerify|jwt\.verify|verifyJwt/,
          label: "JWT verification (verify algorithm pinning)",
        },
        {
          regex: /SignJWT|jwt\.sign|jwtSign|createBypassJwt/,
          label: "JWT signing (verify key management)",
        },
        { regex: /jwtDecrypt|jwtEncrypt|EncryptJWT/, label: "JWT encryption (verify algorithm)" },
        {
          regex: /cookie.*secret|SESSION_COOKIE|USER_CACHE_COOKIE/,
          label: "Session cookie handling",
        },
        {
          regex: /refreshToken|force_refresh_access_token/,
          label: "Token refresh logic (verify validation)",
        },
        {
          regex: /algorithm.{0,40}none|alg.{0,40}none/i,
          label: "JWT 'none' algorithm (CRITICAL if not test)",
        },
      ],
      content,
    );
  },
};

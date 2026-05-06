import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

export const algorithmConfusionMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "algorithm-confusion",
  description: "JWT verification without algorithm pinning — algorithm confusion attack risk",
  filePatterns: ["**/*.{ts,tsx,js,jsx,lua}"],
  examples: [
    `const decoded = jwt.verify(token, secret);`,
    `const result = await jwtVerify(token, key);`,
    `const claims = verifyJwt(token, publicKey);`,
    `local ok = jwt_obj:verify(secret, token)`,
    `jwt.verify(token, key, { algorithms: ["RS256"] });`,
    `await jwtVerify(token, jwks, { algorithm: "HS256" });`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    const hasJwtVerify = /jwt\.verify|jwtVerify|verifyJwt|jwt_obj:verify|resty\.jwt/.test(content);
    if (!hasJwtVerify) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      if (/jwt\.verify|jwtVerify|verifyJwt|jwt_obj:verify/.test(lines[i])) {
        const window = lines.slice(i, Math.min(lines.length, i + 5)).join("\n");
        const hasAlgPin = /algorithms\s*:|algorithm\s*:|alg.*RS256|alg.*HS256|alg.*ES256/.test(
          window,
        );

        const start = Math.max(0, i - 1);
        const end = Math.min(lines.length, i + 4);
        matches.push({
          vulnSlug: "algorithm-confusion",
          lineNumbers: [i + 1],
          snippet: lines.slice(start, end).join("\n"),
          matchedPattern: hasAlgPin
            ? "JWT verification with algorithm pin (verify correct algorithm)"
            : "JWT verification WITHOUT algorithm pinning — algorithm confusion risk",
        });
      }
    }

    return matches;
  },
};

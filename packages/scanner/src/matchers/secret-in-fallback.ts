import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const secretInFallbackMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "secret-in-fallback",
  description:
    "Environment variable secrets with hardcoded fallback values — bypass when env unset",
  filePatterns: ["**/*.{ts,tsx,js,jsx}"],
  examples: [
    `const s = process.env.JWT_SECRET ?? "dev-secret";`,
    `const t = process.env.API_TOKEN ?? "fallback";`,
    `const k = process.env.STRIPE_KEY ?? "sk_test";`,
    `const p = process.env.DB_PASSWORD ?? "changeme";`,
    `const a = process.env.AUTH_CREDENTIAL ?? "open";`,
    `const s = process.env.HMAC_SECRET || "default";`,
    `const t = process.env.GITHUB_TOKEN || "ghp_fallback";`,
    `const k = process.env.PRIVATE_KEY || "----";`,
    `local s = os.getenv("API_SECRET") or "dev"`,
    `local t = os.getenv("HMAC_TOKEN") or "fallback"`,
    `local k = os.getenv("OAUTH_KEY") or "stub"`,
    `local p = os.getenv("DB_PASSWORD") or "changeme"`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    return regexMatcher(
      "secret-in-fallback",
      [
        {
          regex:
            /process\.env\.\w*(SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL|AUTH)\w*\s*\?\?\s*['"][^'"]*['"]/,
          label: "Secret env var with ?? fallback",
        },
        {
          regex:
            /process\.env\.\w*(SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL|AUTH)\w*\s*\|\|\s*['"][^'"]*['"]/,
          label: "Secret env var with || fallback",
        },
        {
          regex: /os\.getenv\s*\(\s*["']\w*(SECRET|TOKEN|KEY|PASSWORD).*\)\s*or\s+["']/,
          label: "Lua env var with 'or' fallback",
        },
      ],
      content,
    );
  },
};

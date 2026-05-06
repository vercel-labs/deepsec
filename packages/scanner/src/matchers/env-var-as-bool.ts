import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const envVarAsBoolMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "env-var-as-bool",
  description: "Security env vars checked with truthy/falsy — 'false' string is truthy in JS",
  filePatterns: ["**/*.{ts,tsx,js,jsx}"],
  examples: [
    `if (process.env.DISABLE_AUTH) skipAuth();`,
    `if (!process.env.SKIP_AUTH_CHECK) doAuth();`,
    `if (process.env.BYPASS_AUTH) return next();`,
    `if (process.env.NO_AUTH) return next();`,
    `if (process.env.DISABLE_VERIFY) bypassed = true;`,
    `if (!process.env.SKIP_VALIDATE) validate();`,
    `if (process.env.BYPASS_CHECK) doStuff();`,
    `if (process.env.ENABLE_AUTH) attachAuth();`,
    `if (process.env.REQUIRE_AUTH) doAuth();`,
    `const token = process.env.MY_SECRET;`,
    `auth(process.env.API_TOKEN);`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    return regexMatcher(
      "env-var-as-bool",
      [
        {
          regex: /if\s*\(\s*!?\s*process\.env\.\w*(DISABLE|SKIP|BYPASS|NO_)\w{0,40}AUTH/i,
          label: "Security disable flag checked as truthy",
        },
        {
          regex:
            /if\s*\(\s*!?\s*process\.env\.\w*(DISABLE|SKIP|BYPASS|NO_)\w{0,40}(VERIFY|CHECK|VALIDATE)/i,
          label: "Verification disable flag checked as truthy",
        },
        {
          regex: /if\s*\(\s*process\.env\.\w*(ENABLE|REQUIRE)\w{0,40}AUTH\b/i,
          label: "Auth enable flag — falsy when unset",
        },
        {
          regex: /process\.env\.\w*(SECRET|TOKEN|KEY)\w*\s*[^!=?|&]/,
          label: "Secret env var used as boolean",
        },
      ],
      content,
    );
  },
};

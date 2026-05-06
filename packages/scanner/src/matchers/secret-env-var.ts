import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const secretEnvVarMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "secret-env-var",
  description: "Direct access to secret environment variables — review handling and exposure",
  filePatterns: ["**/*.{lua,go,ts,js}"],
  examples: [
    `local s = os.getenv("API_SECRET")`,
    `local s = os.getenv("HMAC_SECRET")`,
    `local k = os.getenv("DB_MASTER_KEY")`,
    `local k = os.getenv("KMS_MASTER_KEY")`,
    `local a = os.getenv("AWS_SECRET_ACCESS_KEY")`,
    `local p = os.getenv("RSA_PRIVATE_KEY")`,
    `s := os.Getenv("API_SECRET")`,
    `k := os.Getenv("DB_MASTER_KEY")`,
    `a := os.Getenv("AWS_SECRET_ACCESS_KEY")`,
    `const s = process.env.JWT_SECRET;`,
    `const j = process.env.JWE_SECRET;`,
    `const p = process.env.PURGE_API_SECRET;`,
    `const c = process.env.COSMOSDB_MASTER_KEY;`,
  ],
  match(content, filePath) {
    if (/_test\.|_spec\.|\.test\.|\.spec\./.test(filePath)) return [];

    return regexMatcher(
      "secret-env-var",
      [
        // Lua
        { regex: /os\.getenv\s*\(\s*["'][^"']{0,80}SECRET/, label: "Lua os.getenv for SECRET" },
        {
          regex: /os\.getenv\s*\(\s*["'][^"']{0,80}MASTER_KEY/,
          label: "Lua os.getenv for MASTER_KEY",
        },
        {
          regex: /os\.getenv\s*\(\s*["'][^"']{0,80}AWS_SECRET/,
          label: "Lua os.getenv for AWS_SECRET",
        },
        {
          regex: /os\.getenv\s*\(\s*["'][^"']{0,80}PRIVATE_KEY/,
          label: "Lua os.getenv for PRIVATE_KEY",
        },
        // Go
        { regex: /os\.Getenv\s*\(\s*"[^"]{0,80}SECRET/, label: "Go os.Getenv for SECRET" },
        { regex: /os\.Getenv\s*\(\s*"[^"]{0,80}MASTER_KEY/, label: "Go os.Getenv for MASTER_KEY" },
        { regex: /os\.Getenv\s*\(\s*"[^"]{0,80}AWS_SECRET/, label: "Go os.Getenv for AWS_SECRET" },
        // TS/JS
        {
          regex: /process\.env\.\w*(JWT_SECRET|JWE_SECRET|PURGE_API_SECRET|COSMOSDB_MASTER_KEY)/,
          label: "Secret env var access",
        },
      ],
      content,
    );
  },
};

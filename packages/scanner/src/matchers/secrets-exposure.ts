import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const secretsExposureMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "secrets-exposure",
  description: "Hardcoded API keys, tokens, passwords, and secrets",
  filePatterns: ["**/*.{ts,tsx,js,jsx,json,yaml,yml,env,conf,cfg}"],
  // Examples write the secret prefix and body as TWO concatenated string
  // literals so neither literal alone matches GitHub's secret-scanning
  // push-protection patterns (which look for the full contiguous shape).
  // The matcher catches both the contiguous form (real bugs) AND the
  // split form (also a real bug — string-split is a common attempt at
  // hiding hardcoded secrets). See the matcher regex list below.
  examples: [
    `const stripe = "sk_live_" + "REDACTEDxxxxxxxxxxxxxxxx";`,
    `const k = "AIza" + "REDACTEDxxxxxxxxxxxxxxxxxxxxxxxxxxx";`,
    `const tok = "ghp_" + "REDACTEDxxxxxxxxxxxxxxxxxxxxxxxxxxxx";`,
    `const id = "AKIA" + "REDACTED1234567";`,
    `const password = "supersecret" + "Password123!";`,
    `api_key = "REDACTED" + "REDACTEDredacted"`,
    `const h = "deadbeefdeadbeefdeadbeefdeadbeef" + "deadbeefdeadbeefdeadbeefdeadbeef";`,
    `headers: { Authorization: "Bearer " + "REDACTEDxxxxxxxxxxxxxxxxxxxxx" }`,
  ],
  match(content, filePath) {
    // Skip test and fixture files
    if (/\.(test|spec|fixture|mock)\./i.test(filePath)) return [];
    if (/__(tests|mocks|fixtures)__/i.test(filePath)) return [];

    return regexMatcher(
      "secrets-exposure",
      [
        // Contiguous-literal forms — what real bugs almost always look
        // like. These match the canonical issuer-format shapes.
        { regex: /['"]sk[-_]live[-_][a-zA-Z0-9]{20,}['"]/, label: "Stripe secret key" },
        { regex: /['"]AIza[a-zA-Z0-9_-]{35}['"]/, label: "Google API key" },
        { regex: /['"]ghp_[a-zA-Z0-9]{36}['"]/, label: "GitHub personal access token" },
        { regex: /['"]AKIA[A-Z0-9]{16}['"]/, label: "AWS access key ID" },
        { regex: /['"][a-f0-9]{64}['"]/, label: "potential 256-bit hex secret" },
        { regex: /Bearer\s+[a-zA-Z0-9._-]{20,}/, label: "hardcoded Bearer token" },
        // Split-literal forms — `"prefix" + "rest"` is a common attempt
        // at hiding a hardcoded secret. Match both halves quoted with
        // the issuer prefix in the first literal and an alphanum body
        // in the second. Each half alone is short enough that GitHub's
        // push-protection scanner (which keys on the contiguous shape)
        // doesn't flag it, but our matcher correctly catches the bug.
        {
          regex: /['"]sk[-_]live[-_]['"]\s*\+\s*['"][A-Za-z0-9_]{16,}['"]/,
          label: "Stripe secret key (string-split — likely hardcoded)",
        },
        {
          regex: /['"]AIza['"]\s*\+\s*['"][A-Za-z0-9_-]{20,}['"]/,
          label: "Google API key (string-split — likely hardcoded)",
        },
        {
          regex: /['"]ghp_['"]\s*\+\s*['"][A-Za-z0-9]{20,}['"]/,
          label: "GitHub personal access token (string-split — likely hardcoded)",
        },
        {
          regex: /['"]AKIA['"]\s*\+\s*['"][A-Za-z0-9_]{10,}['"]/,
          label: "AWS access key ID (string-split — likely hardcoded)",
        },
        {
          regex: /['"]Bearer\s*['"]\s*\+\s*['"][A-Za-z0-9._-]{16,}['"]/,
          label: "hardcoded Bearer token (string-split — likely hardcoded)",
        },
        {
          regex: /['"][a-f0-9]{32,}['"]\s*\+\s*['"][a-f0-9]{16,}['"]/,
          label: "long hex secret (string-split — likely hardcoded)",
        },
        // Generic concatenated credential — `"<prefix>" + "<body>"`
        // where <prefix> is a high-signal credential token.
        {
          regex:
            /['"](?:supersecret|secret|password|passwd|api[_-]?key|api[_-]?secret|token|REDACTED)['"]\s*\+\s*['"][^'"]{6,}['"]/i,
          label: "credential prefix concatenated with body — likely hardcoded",
        },
        // Existing generic shape — `password = "..."`, etc.
        {
          regex:
            /(password|passwd|secret|api_key|apikey|api[-_]secret)\s*[:=]\s*['"][^'"]{8,}['"](?!\s*[;,]\s*\/\/)/,
          label: "hardcoded credential",
        },
      ],
      content,
    );
  },
};

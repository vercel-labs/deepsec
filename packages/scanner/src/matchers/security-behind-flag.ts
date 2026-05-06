import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

export const securityBehindFlagMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "security-behind-flag",
  description: "Security-critical code gated by feature flags — fails open when flag is off",
  filePatterns: ["**/*.{ts,tsx,js,jsx,lua,go}"],
  examples: [
    `if (featureFlag("strict-auth")) {
  await verifyToken(req);
}`,
    `if (feature_flag.is_enabled("waf")) {
  await firewallCheck(req);
}`,
    `if (LaunchDarkly.variation("rate-limit", false)) {
  throttle(req);
}`,
    `const variant = client.variation("csrf-check");
if (variant) {
  validateCsrf(req);
}`,
    `if (statsig.checkGate("strip-headers")) {
  sanitize(req.headers);
}`,
    `if (flag_enabled("encryption")) {
  encrypt(payload);
}`,
    `if (isEnabled("auth-required")) {
  await verifyToken(req);
}`,
    `if (isFeatureEnabled("rate-limit")) {
  throttle(req);
}`,
    `const flag = experiment("hmac-check");
if (flag) {
  hmac(secret, body);
}`,
    `if (getFlag("strict-cors")) {
  applyCors(req);
}`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    const flagPatterns = [
      /feature_?flag|featureFlag|LaunchDarkly|variation\s*\(|statsig|flag_enabled/i,
      /isEnabled\s*\(|isFeatureEnabled/,
      /experiment\s*\(|getFlag\s*\(/,
    ];

    const securityPatterns = [
      /sanitize|strip.*header|clear_header|remove.*header/i,
      /auth|verify|validate.*token|check.*permission/i,
      /waf|firewall|block|deny|reject/i,
      /rate.?limit|throttle/i,
      /csrf|cors|xss|injection/i,
      /encrypt|decrypt|sign|hmac/i,
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const hasFlag = flagPatterns.some((p) => p.test(line));
      if (!hasFlag) continue;

      // Check surrounding context (3 lines before and after) for security operations
      const context = lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 4)).join("\n");
      const hasSecurity = securityPatterns.some((p) => p.test(context));

      if (hasSecurity) {
        const start = Math.max(0, i - 2);
        const end = Math.min(lines.length, i + 3);
        matches.push({
          vulnSlug: "security-behind-flag",
          lineNumbers: [i + 1],
          snippet: lines.slice(start, end).join("\n"),
          matchedPattern:
            "Security operation gated by feature flag — verify fail-safe when flag is off",
        });
      }
    }

    return matches;
  },
};

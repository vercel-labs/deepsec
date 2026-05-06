import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const luaCryptoWeaknessMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "lua-crypto-weakness",
  description: "Weak crypto patterns in Lua — hardcoded IVs, ECB mode, timing-unsafe comparisons",
  filePatterns: ["**/*.lua"],
  examples: [
    `local cipher = aes:new(key, "cbc", "ecb")`,
    `if computed_hmac == provided_hmac then end`,
    `if hmac_value == header_token then return true end`,
    `if hash_value == expected_hash then end`,
    `local digest = md5(payload)`,
    `local h = ngx.sha1(data)`,
    `local iv = "0123456789abcdef"`,
    `local d = ngx.md5(payload)`,
  ],
  match(content, filePath) {
    if (/_test\.lua$|_spec\.lua$/.test(filePath)) return [];

    return regexMatcher(
      "lua-crypto-weakness",
      [
        { regex: /aes.{0,40}ecb|ecb.{0,40}aes/i, label: "AES ECB mode (no IV, deterministic)" },
        {
          regex: /==\s*.{0,40}hmac|hmac.{0,40}==/,
          label: "Timing-unsafe HMAC comparison (use constant-time)",
        },
        { regex: /==\s*.{0,40}hash|hash.{0,40}==/, label: "Timing-unsafe hash comparison" },
        { regex: /md5\s*\(|\.md5/, label: "MD5 usage" },
        { regex: /sha1\s*\(|\.sha1\b/, label: "SHA1 usage" },
        { regex: /local\s+iv\s*=\s*["']/, label: "Hardcoded IV value" },
      ],
      content,
    );
  },
};

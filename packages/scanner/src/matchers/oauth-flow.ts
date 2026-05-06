import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const oauthFlowMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "oauth-flow",
  description: "OAuth authorize/callback endpoints and token-bearing redirects",
  filePatterns: [
    "**/oauth/**/*.{ts,tsx}",
    "**/auth/**/*.{ts,tsx}",
    "**/callback/**/*.{ts,tsx}",
    "**/app/api/**/*.{ts,tsx}",
    "**/api/**/*.{ts,tsx}",
  ],
  examples: [
    `const redirect_uri = req.query.redirect_uri;`,
    `params.append("redirect_uri", url);`,
    `body.set("grant_type", "authorization_code");`,
    `const grantType = "authorization_code";`,
    `params.set("code_verifier", verifier);`,
    `const code_challenge = sha256(code_verifier);`,
    `const u = "https://idp/cb?state=" + s + "&redirect=" + r;`,
    `// redirect handler with state= param parsing`,
    `const url = "https://app/cb?code=" + c;`,
    `if (qs.includes("&code=")) handle();`,
    `// access_token in redirect URL`,
    `// access_token returned via callback URL token=`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    const isOAuthPath = /oauth|callback|authorize/i.test(filePath);
    const hasOAuthCode =
      /redirect_uri|authorization_code|code_verifier|state=|code=|access_token/.test(content);

    if (!isOAuthPath && !hasOAuthCode) return [];

    return regexMatcher(
      "oauth-flow",
      [
        { regex: /redirect_uri/, label: "OAuth redirect_uri handling" },
        { regex: /authorization_code|grant_type/, label: "OAuth authorization code flow" },
        { regex: /code_verifier|code_challenge/, label: "PKCE flow" },
        {
          regex: /state=.{0,80}redirect|redirect.{0,80}state=/,
          label: "OAuth state + redirect",
        },
        { regex: /\?code=|&code=/, label: "Authorization code in URL" },
        {
          regex: /access_token.{0,80}redirect|redirect.{0,80}access_token/,
          label: "Token in redirect URL",
        },
        {
          regex: /callback.{0,80}token|token.{0,80}callback/,
          label: "Token in callback",
        },
      ],
      content,
    );
  },
};

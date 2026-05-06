import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Session cookie misconfiguration. Auth cookies should be:
 *   - `httpOnly: true`        → not readable from client JS (mitigates XSS theft)
 *   - `secure: true`          → only sent over HTTPS
 *   - `sameSite: 'lax'|'strict'` → mitigates CSRF
 *   - Reasonable `maxAge` / `expires`
 *
 * Flags `cookies.set(...)` and library config (Better Auth, NextAuth,
 * iron-session, lucia) that establishes the session cookie. Reviewer
 * verifies the actual options when checking the candidate.
 */
export const sessionCookieConfigMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "session-cookie-config",
  description: "Session/auth cookie configuration — verify httpOnly + sameSite + secure",
  filePatterns: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.mjs"],
  examples: [
    `import { cookies } from "next/headers";
cookies().set("session", token, { httpOnly: true });`,
    `import { cookies } from "next/headers";
cookies().set({ name: "auth", value: token });`,
    `import session from "iron-session";
res.cookie("auth", token, { secure: true });`,
    `import { betterAuth } from "better-auth";
response.cookie("session", token);`,
    `import NextAuth from "next-auth";
const auth = new NextAuth({ providers: [] });`,
    `import { Lucia } from "lucia";
const lucia = new Lucia(adapter, {
  sessionCookie: { attributes: { secure: true } },
});`,
    `import { betterAuth } from "better-auth";
export const auth = betterAuth({
  cookieOptions: { secure: true, httpOnly: true },
});`,
    `import session from "iron-session";
const ironOptions = { cookieName: "session", password: "x" };`,
    `import { ironSession } from "iron-session/express";
ironSession({ cookieName: "session", password: "x" });`,
    `import { cookies } from "next/headers";
res.setHeader("Set-Cookie", \`session=\${token}; HttpOnly\`);`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)$/.test(filePath)) return [];
    if (/\.d\.ts$/.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    const HAS_AUTH_LIB =
      /\bfrom\s+["'](?:better-auth|next-auth|@auth\/core|iron-session|lucia|@lucia-auth|@clerk\/(?:nextjs|backend))[^"']*["']|\bcookies\(\)\s*\.\s*set\s*\(|\bres\.\s*setHeader\s*\(\s*["']Set-Cookie/i;
    if (!HAS_AUTH_LIB.test(content)) return [];

    const lines = content.split("\n");
    const matches: CandidateMatch[] = [];

    const PATTERNS: { regex: RegExp; label: string }[] = [
      {
        regex: /\bcookies\(\)\s*\.\s*set\s*\(/,
        label: "next/headers cookies().set() — verify cookie options",
      },
      {
        regex: /\bres\.\s*cookie\s*\(|\bresponse\.\s*cookie\s*\(/,
        label: "res.cookie() — verify httpOnly+secure+sameSite",
      },
      {
        regex: /\bnew\s+(?:NextAuth|BetterAuth|Lucia)\s*\(/,
        label: "Auth library construction — review cookie config",
      },
      {
        regex: /\bsessionCookie\s*:\s*\{|\bcookieOptions\s*:\s*\{|\bcookies\s*:\s*\{/,
        label: "Cookie options block",
      },
      { regex: /\bironOptions\s*=\s*\{|\bironSession\s*\(/, label: "iron-session config" },
      {
        regex: /\bsetHeader\s*\(\s*["']Set-Cookie["']/,
        label: "Raw Set-Cookie header — verify flags",
      },
    ];

    const seen = new Set<number>();
    for (let i = 0; i < lines.length; i++) {
      for (const { regex, label } of PATTERNS) {
        if (regex.test(lines[i])) {
          if (seen.has(i)) continue;
          seen.add(i);
          const start = Math.max(0, i - 1);
          const end = Math.min(lines.length, i + 8);
          matches.push({
            vulnSlug: "session-cookie-config",
            lineNumbers: [i + 1],
            snippet: lines.slice(start, end).join("\n"),
            matchedPattern: label,
          });
        }
      }
    }
    return matches;
  },
};

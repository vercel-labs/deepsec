import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

export const secretInLogMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "secret-in-log",
  description:
    "Credentials or tokens appearing in log statements or error messages returned to callers",
  filePatterns: ["**/*.{ts,tsx,js,jsx}"],
  examples: [
    `console.log("token", token);`,
    `console.error("failed:", apiKey);`,
    `console.warn("auth", refreshToken);`,
    `console.info("got", accessToken);`,
    `logger.info({ secret });`,
    `logger.error({ password });`,
    `migrationsLogger.warn({ apiKey });`,
    `log.debug({ credential });`,
    `({ token, foo })`,
    `({ secret: v })`,
    `JSON.stringify({ token: t });`,
    `throw new Error("token=" + token);`,
    `res.json({ token });`,
    `res.send({ secret });`,
    `return { error: "missing token" };`,
    `return { message: "credential rejected" };`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    const secretNames =
      /\b(token|accessToken|refreshToken|secret|apiKey|api_key|password|credential|privateKey|bearerToken)\b/;
    const logPatterns = [
      /console\.(log|error|warn|info)\s*\(/,
      /logger\.\w+\s*\(/,
      /migrationsLogger\.\w+\s*\(/,
      /log\.\w+\s*\(/,
      /\{\s*(token|secret|apiKey|password|credential|accessToken|refreshToken)\s*[,}:]/, // structured logging
      /JSON\.stringify\s*\(.*\b(token|secret|key|password)\b/,
    ];
    const errorReturnPatterns = [
      /throw\s+new\s+\w*Error\s*\(/,
      /res\.(json|send|status)\s*\(/,
      /return.*\{.*error/,
      /return.*message.*:/,
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!secretNames.test(line)) continue;

      const isLog = logPatterns.some((p) => p.test(line));
      const isErrorReturn = errorReturnPatterns.some((p) => p.test(line));

      if (isLog || isErrorReturn) {
        const start = Math.max(0, i - 1);
        const end = Math.min(lines.length, i + 2);
        matches.push({
          vulnSlug: "secret-in-log",
          lineNumbers: [i + 1],
          snippet: lines.slice(start, end).join("\n"),
          matchedPattern: isLog
            ? "Secret variable in log statement"
            : "Secret variable in error response",
        });
      }
    }

    return matches;
  },
};

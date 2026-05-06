import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Detects error messages being returned to clients in API responses.
 * Internal errors can leak infrastructure details, stack traces, DB schemas.
 */
export const errorMessageLeakMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "error-message-leak",
  description: "Error messages returned to client — may leak internal details",
  filePatterns: [
    "**/app/api/**/route.{ts,tsx}",
    "**/app/**/route.{ts,tsx}",
    "**/pages/api/**/*.{ts,tsx}",
    "**/routes/**/*.{ts,tsx}",
    "**/endpoints/**/*.{ts,tsx}",
  ],
  examples: [
    `try { run(); } catch (err) {
  return Response.json({ error: err.message });
}`,
    `try { run(); } catch (error) {
  return NextResponse.json({ message: error.message }, { status: 500 });
}`,
    `try { run(); } catch (err) {
  return Response.json({ stack: err.stack });
}`,
    `try { run(); } catch (error) {
  return res.json({ trace: error.stack });
}`,
    `try { run(); } catch (err) {
  return res.send(err.toString());
}`,
    `try { run(); } catch (err) {
  return Response.json({ error: String(err) });
}`,
  ],
  match(content, filePath) {
    if (/\.(test|spec|mock|stub)\./i.test(filePath)) return [];
    if (/node_modules|\.next|dist\//.test(filePath)) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    const leakPatterns: { regex: RegExp; label: string }[] = [
      { regex: /err(or)?\.message/, label: "error.message in response" },
      { regex: /err(or)?\.stack/, label: "error.stack in response" },
      { regex: /\.toString\(\)/, label: "error.toString() in response" },
      { regex: /String\(err/, label: "String(error) in response" },
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const { regex, label } of leakPatterns) {
        if (!regex.test(line)) continue;
        // Check if it's near a Response/json/send (within 3 lines)
        const context = lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 3)).join("\n");
        if (
          /Response\.json|NextResponse\.json|res\.json|res\.send|res\.status|new Response|json\s*\(/.test(
            context,
          )
        ) {
          const start = Math.max(0, i - 2);
          const end = Math.min(lines.length, i + 3);
          matches.push({
            vulnSlug: "error-message-leak",
            lineNumbers: [i + 1],
            snippet: lines.slice(start, end).join("\n"),
            matchedPattern: `${label} — may leak internal details to client`,
          });
          break;
        }
      }
    }

    return matches;
  },
};

import type { MatcherPlugin } from "@deepsec/core";
import { describe, expect, it } from "vitest";
import { createDefaultRegistry } from "../matchers/index.js";

/**
 * Auto-discovered fixture test: every matcher that ships an `examples`
 * array must produce ≥ 1 candidate for each example string. A typo in
 * any sub-pattern of any matcher's regex list fails this test —
 * provided the broken pattern is exercised by at least one example.
 *
 * Adding a new example: one line in the matcher file's `examples: [...]`
 * array. No test wiring required.
 */

/**
 * Pick a plausible-looking file path for a given matcher. Some matchers
 * gate on the path (rejecting `_test.go`, `node_modules`, etc.) or on
 * the file extension via `filePatterns`. We synthesize a path that
 * passes every reasonable gate.
 */
function sampleFilePath(matcher: MatcherPlugin): string {
  // Some matchers gate internally on a specific framework directory or
  // filename even though their `filePatterns` are broad (e.g. `**/*.ts`).
  // Provide explicit overrides keyed by slug for those cases.
  const slugOverrides: Record<string, string> = {
    "framework-untrusted-fetch": "packages/next/src/server/example.ts",
    "framework-image-optimizer": "packages/next/src/server/image-optimizer.ts",
    "framework-edge-sandbox": "packages/next/src/server/web/sandbox/example.ts",
    "framework-server-action": "packages/next/src/server/app-render/action-handler.ts",
    "cron-secret-check": "src/app/api/cron/route.ts",
  };
  if (slugOverrides[matcher.slug]) return slugOverrides[matcher.slug];

  // SvelteKit / Nuxt / Astro use literal-named files; honor those.
  for (const p of matcher.filePatterns) {
    if (p.includes("+page.server")) return "src/routes/foo/+page.server.ts";
    if (p.includes("+server")) return "src/routes/api/+server.ts";
    if (p.includes("+layout.server")) return "src/routes/+layout.server.ts";
    if (p.endsWith("AndroidManifest.xml")) return "app/src/main/AndroidManifest.xml";
    if (p.endsWith("Info.plist")) return "ios/Info.plist";
    if (p.endsWith("function.json")) return "fn/function.json";
    if (p.endsWith("config/routes.rb")) return "config/routes.rb";
    // Next.js App Router conventions — many matchers gate on these literal
    // filenames as well as the brace extension list. Order matters: check
    // catch-all and protected-group patterns before plain route/page.
    if (p.includes("[[...") || p.includes("[...")) return "src/app/api/[[...rest]]/route.ts";
    if (p.includes("(payload)")) return "src/app/(payload)/api/route.ts";
    if (p.includes("graphql/route")) return "src/app/api/graphql/route.ts";
    if (p.includes("(protected)")) return "src/app/(protected)/api/foo/route.ts";
    if (p.includes("(dashboard)")) return "src/app/(dashboard)/api/foo/route.ts";
    if (p.includes("(auth)")) return "src/app/(auth)/api/foo/route.ts";
    if (p.includes("app/api/") && p.includes("route.")) return "src/app/api/foo/route.ts";
    if (p.includes("middleware.")) return "src/middleware.ts";
    if (p.includes("route.")) return "src/app/api/foo/route.ts";
    if (p.includes("app/") && p.includes("page.")) return "src/app/foo/page.tsx";
    if (p.includes("actions.")) return "src/app/actions.ts";
  }
  const ext = pickExtension(matcher.filePatterns);
  // `src/` is universally accepted; nothing in our matcher set treats
  // it as a generated/vendor path. The basename `example` is short and
  // matches no skip-list entry.
  return ext === null ? `src/example` : `src/example${ext}`;
}

/**
 * Pull a representative file extension from the matcher's
 * filePatterns. Tries the brace form (e.g. *.{ts,tsx}) first, then the
 * single-extension form. Some matchers target specific filenames (e.g.
 * AndroidManifest.xml, Info.plist) — those are handled separately.
 */
function pickExtension(patterns: string[]): string | null {
  for (const p of patterns) {
    // `**/*.{ts,tsx,js}` or `**/foo.{ts,js}` style — pick first listed.
    const braced = p.match(/\.\{([^}]+)\}/);
    if (braced) {
      const first = braced[1].split(",")[0].trim();
      return "." + first;
    }
    // `**/*.go` / `**/*.tf` etc.
    const single = p.match(/\*\.([a-zA-Z0-9]+)$/);
    if (single) return "." + single[1];
  }
  return null;
}

const registry = createDefaultRegistry();
const matchersWithExamples: MatcherPlugin[] = registry
  .getAll()
  .filter(
    (m): m is MatcherPlugin & { examples: string[] } =>
      Array.isArray(m.examples) && m.examples.length > 0,
  );

describe("matcher inline examples", () => {
  it("at least some matchers ship examples", () => {
    // Sanity check that the discovery wired up — once we backfill
    // every matcher this becomes a stronger floor (e.g. ≥ 80% of
    // matchers must have examples).
    expect(matchersWithExamples.length).toBeGreaterThan(0);
  });

  for (const matcher of matchersWithExamples) {
    describe(matcher.slug, () => {
      const filePath = sampleFilePath(matcher);
      for (let i = 0; i < (matcher.examples ?? []).length; i++) {
        const example = (matcher.examples as string[])[i];
        const preview = example.length > 60 ? example.slice(0, 57) + "…" : example;
        const safePreview = preview.replace(/\s+/g, " ");
        it(`#${i} fires on: ${safePreview}`, () => {
          const result = matcher.match(example, filePath);
          expect(
            result.length,
            `Expected matcher "${matcher.slug}" to fire on example #${i} but got 0 candidates.\n` +
              `  Example: ${JSON.stringify(example)}\n` +
              `  File path: ${filePath}\n` +
              `  Either add the missing pattern to the matcher, or fix the example.`,
          ).toBeGreaterThan(0);
        });
      }
    });
  }
});

import { describe, expect, it } from "vitest";
import { MatcherRegistry } from "../matcher-registry.js";
import type { MatcherPlugin } from "../types.js";

function matcher(slug: string): MatcherPlugin {
  return {
    slug,
    description: "test matcher",
    noiseTier: "precise",
    filePatterns: ["**/*.ts"],
    match: () => [],
  };
}

describe("MatcherRegistry", () => {
  it("rejects duplicate slugs by default", () => {
    const registry = new MatcherRegistry();
    const first = matcher("duplicate");
    const second = matcher("duplicate");
    registry.register(first);

    expect(() => registry.register(second)).toThrow(/already registered/);
    expect(registry.getBySlug("duplicate")).toBe(first);
  });

  it("allows explicit overrides only", () => {
    const registry = new MatcherRegistry();
    const first = matcher("duplicate");
    const second = matcher("duplicate");
    registry.register(first);
    registry.register(second, { allowOverride: true });

    expect(registry.getBySlug("duplicate")).toBe(second);
  });
});

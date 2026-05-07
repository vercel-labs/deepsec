import type { MatcherPlugin } from "./types.js";

export class MatcherRegistry {
  private matchers = new Map<string, MatcherPlugin>();

  register(plugin: MatcherPlugin): void {
    this.matchers.set(plugin.slug, plugin);
  }

  getAll(): MatcherPlugin[] {
    return Array.from(this.matchers.values());
  }

  getBySlug(slug: string): MatcherPlugin | undefined {
    return this.matchers.get(slug);
  }

  getBySlugs(slugs: string[]): MatcherPlugin[] {
    const missing = slugs.filter((slug) => !this.matchers.has(slug));
    if (missing.length > 0) {
      throw new Error(`Unknown matcher slug(s): ${missing.join(", ")}`);
    }
    return slugs.map((slug) => this.matchers.get(slug)!);
  }

  slugs(): string[] {
    return Array.from(this.matchers.keys());
  }
}

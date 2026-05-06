import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const rsPoemRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "rs-poem-route",
  description: "Poem route handlers (gated on Poem)",
  filePatterns: ["**/*.rs"],
  requires: { tech: ["poem"] },
  examples: [
    `let app = Route::new().at("/hello", get(hello));`,
    `Route::new().at("/users/:id", get(show_user).post(update_user))`,
    `Route::new().at("/login", post(login_handler))`,
    `#[handler]`,
    `#[ handler ]`,
    `let route = get(index);`,
    `Route::new().at("/items", post(create_item).delete(delete_item))`,
    `let r = patch(handler);`,
  ],
  match(content, filePath) {
    if (/\/(tests|examples)\//.test(filePath)) return [];

    return regexMatcher(
      "rs-poem-route",
      [
        {
          regex: /\bRoute::new\s*\(\s*\)\.at\s*\(\s*"[^"]+"\s*,/,
          label: "Route::new().at('/path', ...)",
        },
        {
          regex: /#\[\s*handler\s*\]/,
          label: "#[handler] attribute",
        },
        {
          regex: /\bget\s*\(|post\s*\(|put\s*\(|patch\s*\(|delete\s*\(/,
          label: "handler verb wrapper",
        },
      ],
      content,
    );
  },
};

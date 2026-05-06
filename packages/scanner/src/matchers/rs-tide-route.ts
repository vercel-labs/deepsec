import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const rsTideRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "rs-tide-route",
  description: "Tide route handlers (gated on Tide)",
  filePatterns: ["**/*.rs"],
  requires: { tech: ["tide"] },
  examples: [
    `app.at("/users").get(list_users);`,
    `app.at("/login").post(handle_login);`,
    `app.at("/items/:id").put(update_item);`,
    `app.at("/items/:id").delete(remove_item);`,
    `app.at("/all").all(any_handler);`,
    `let mut app = tide::new();`,
    `impl Middleware<State> for AuthGuard {`,
    `use tide::Middleware;`,
  ],
  match(content, filePath) {
    if (/\/(tests|examples)\//.test(filePath)) return [];

    return regexMatcher(
      "rs-tide-route",
      [
        {
          regex: /\bapp\.at\s*\(\s*"[^"]+"\s*\)\.(?:get|post|put|patch|delete|all)\s*\(/,
          label: "app.at('/path').<verb>(handler)",
        },
        { regex: /\btide::new\s*\(\s*\)/, label: "tide::new() factory" },
        { regex: /\bMiddleware\b/, label: "Middleware trait — auth wiring" },
      ],
      content,
    );
  },
};

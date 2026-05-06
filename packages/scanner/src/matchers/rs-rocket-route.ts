import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const rsRocketRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "rs-rocket-route",
  description: "Rocket route attributes and mount! macro (gated on Rocket)",
  filePatterns: ["**/*.rs"],
  requires: { tech: ["rocket"] },
  examples: [
    `#[get("/world")]`,
    `#[post("/login")]`,
    `#[ put ( "/items/<id>" ) ]`,
    `#[delete("/users/<id>")]`,
    `rocket::routes![index, login, logout]`,
    `rocket.mount("/api", routes![hello])`,
    `fn create(form: Form<NewUser>) -> Status {}`,
    `fn show(id: u32, query: Query<Filter>) -> Json<User> {}`,
  ],
  match(content, filePath) {
    if (/\/(tests|examples)\//.test(filePath)) return [];

    return regexMatcher(
      "rs-rocket-route",
      [
        {
          regex: /#\[\s*(?:get|post|put|patch|delete|head|options)\s*\(\s*"[^"]+"\s*\)/,
          label: "Rocket route attribute",
        },
        { regex: /\brocket::routes!\s*\[/, label: "routes![...] macro" },
        { regex: /\.mount\s*\(\s*"[^"]+"/, label: ".mount() registration" },
        { regex: /Json<[^>]+>|Form<[^>]+>|Query<[^>]+>/, label: "guard / extractor (untrusted)" },
      ],
      content,
    );
  },
};

import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const rsActixRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "rs-actix-route",
  description: "Actix-web route attributes and service registrations (gated on Actix)",
  filePatterns: ["**/*.rs"],
  requires: { tech: ["actix"] },
  examples: [
    `#[get("/users/{id}")]`,
    `#[post("/login")]`,
    `#[ delete ( "/items/{id}" ) ]`,
    `let app = App::new();`,
    `App::new().service(index)`,
    `cfg.service(index);`,
    `web::scope("/api/v1")`,
    `async fn handler(path: web::Path<u32>) -> impl Responder {}`,
    `async fn create(payload: web::Json<UserDto>) {}`,
    `data: web::Data<AppState>`,
  ],
  match(content, filePath) {
    if (/\/(tests|examples)\//.test(filePath)) return [];

    return regexMatcher(
      "rs-actix-route",
      [
        {
          regex: /#\[\s*(?:get|post|put|patch|delete|head|options)\s*\(\s*"[^"]+"\s*\)/,
          label: "Actix route attribute",
        },
        { regex: /App::new\s*\(\s*\)/, label: "App::new() factory" },
        { regex: /\.service\s*\(/, label: ".service(...) registration" },
        { regex: /\bweb::scope\s*\(/, label: "web::scope() group" },
        {
          regex: /web::(?:Path|Query|Json|Form|Data)<[^>]+>/,
          label: "extractor (untrusted input)",
        },
      ],
      content,
    );
  },
};

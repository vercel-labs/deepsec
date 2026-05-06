import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const rsAxumRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "rs-axum-route",
  description: "Axum router declarations (gated on Axum)",
  filePatterns: ["**/*.rs"],
  requires: { tech: ["axum"] },
  examples: [
    `let app = Router::new();`,
    `Router::new().route("/users", get(list_users))`,
    `app.route("/login", post(login_handler))`,
    `.route("/items/:id", patch(update_item))`,
    `.nest("/api", api_router)`,
    `.merge(admin_routes)`,
    `async fn handler(Extension(user): Extension<CurrentUser>) {}`,
    `async fn handler(State(pool): State<PgPool>) {}`,
    `async fn handler(Path(id): Path<u32>) {}`,
    `async fn handler(Query(params): Query<Filter>, Json(body): Json<CreateUserDto>) {}`,
  ],
  match(content, filePath) {
    if (/\/(tests|examples)\//.test(filePath)) return [];

    return regexMatcher(
      "rs-axum-route",
      [
        {
          regex: /\bRouter::new\s*\(\s*\)/,
          label: "Router::new() factory",
        },
        {
          regex: /\.route\s*\(\s*"[^"]+"\s*,\s*(?:get|post|put|patch|delete|any|on)\s*\(/,
          label: ".route('/path', get(handler))",
        },
        { regex: /\.nest\s*\(\s*"[^"]+"/, label: ".nest() subroute" },
        { regex: /\.merge\s*\(/, label: ".merge() router composition" },
        {
          regex: /\bExtension<[^>]+>|\bState<[^>]+>/,
          label: "Extension/State extractor (auth identity)",
        },
        {
          regex: /Path<[^>]+>|Query<[^>]+>|Json<[^>]+>/,
          label: "request extractor (untrusted input)",
        },
      ],
      content,
    );
  },
};

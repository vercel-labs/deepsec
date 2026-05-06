import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const crKemalRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "cr-kemal-route",
  description: "Crystal Kemal route handlers (gated on kemal)",
  filePatterns: ["**/*.cr"],
  requires: { tech: ["kemal"] },
  examples: [
    `get "/" do\n  "Hello World!"\nend`,
    `post "/users" do |env|\n  env.params.json["name"]\nend`,
    `put "/users/:id" do |env|\nend`,
    `patch "/users/:id" do |env|\nend`,
    `delete "/users/:id" do\nend`,
    `options "/users" do\nend`,
    `ws "/chat" do |socket|\nend`,
    `before_all do |env|\n  env.response.content_type = "application/json"\nend`,
    `before_get do |env|\n  env.response.content_type = "application/json"\nend`,
    `before_post do |env|\nend`,
    `before_put do\nend`,
    `before_delete do\nend`,
    `name = env.params.url["name"]`,
    `q = env.params.query["q"]`,
    `body = env.params.json["body"]`,
    `file = env.params.files["upload"]`,
  ],
  match(content, filePath) {
    if (/\/(spec|test)\//.test(filePath)) return [];

    return regexMatcher(
      "cr-kemal-route",
      [
        {
          regex: /^\s*(?:get|post|put|patch|delete|options|ws)\s+"[^"]+"\s+do\b/m,
          label: "Kemal <verb> '/path' do",
        },
        {
          regex: /^\s*before_(?:all|get|post|put|delete)\s+do\b/m,
          label: "before_* do — auth filter",
        },
        { regex: /\benv\.params\.(?:url|query|json|body|files)\b/, label: "env.params accessor" },
      ],
      content,
    );
  },
};

import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const rbHanamiActionMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "rb-hanami-action",
  description: "Hanami action classes (gated on Hanami)",
  filePatterns: ["**/app/actions/**/*.rb", "**/actions/**/*.rb"],
  requires: { tech: ["hanami"] },
  examples: [
    `class Show < Hanami::Action`,
    `class Create < App::Action`,
    `  def handle(request, response)`,
    `  def handle( request , response )`,
    `  include Deps["repositories.user_repo"]`,
    `  include Deps['services.mailer']`,
  ],
  match(content, filePath) {
    if (/\b(?:test|spec)\b/i.test(filePath)) return [];

    return regexMatcher(
      "rb-hanami-action",
      [
        {
          regex: /^class\s+\w+\s*<\s*(?:Hanami::Action|App::Action)\b/m,
          label: "Hanami action subclass",
        },
        {
          regex: /^\s*def\s+handle\s*\(\s*request\s*,\s*response\s*\)/m,
          label: "handle(request, response) entry",
        },
        { regex: /^\s*include\s+Deps\[\s*['"][^'"]+['"]\s*\]/m, label: "Deps[] DI accessor" },
      ],
      content,
    );
  },
};

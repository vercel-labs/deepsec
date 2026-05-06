import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const rbRodaRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "rb-roda-route",
  description: "Roda route trees (gated on Roda)",
  filePatterns: ["**/*.rb"],
  requires: { tech: ["roda"] },
  examples: [
    `class App < Roda`,
    `class Api < Roda`,
    `  r.get "users" do`,
    `  r.post "login" do`,
    `  r.put "items", Integer do |id|`,
    `  r.patch "profile" do`,
    `  r.delete "sessions" do`,
    `  r.on "api" do`,
    `  r.is "healthz" do`,
    `  r.root do`,
    `plugin :render`,
    `plugin :json_parser`,
  ],
  match(content, filePath) {
    if (/\b(?:test|spec)\b/i.test(filePath)) return [];

    return regexMatcher(
      "rb-roda-route",
      [
        {
          regex: /^class\s+\w+\s*<\s*Roda\b/m,
          label: "class < Roda app",
        },
        {
          regex: /\br\.(?:get|post|put|patch|delete|on|is|root)\b/,
          label: "r.<verb>/r.on/r.is route node",
        },
        { regex: /\bplugin\s+:[\w_]+/, label: "Roda plugin (auth/security/render)" },
      ],
      content,
    );
  },
};

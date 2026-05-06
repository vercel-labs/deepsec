import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const rbGrapeEndpointMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "rb-grape-endpoint",
  description: "Grape API endpoints (gated on Grape)",
  filePatterns: ["**/*.rb"],
  requires: { tech: ["grape"] },
  examples: [
    `get :status do`,
    `post :create do`,
    `put :update do`,
    `patch :rename do`,
    `delete :destroy do`,
    `resource :users do`,
    `before do`,
    `  user = User.find(declared(params)[:id])`,
  ],
  match(content, filePath) {
    if (/\b(?:test|spec)\b/i.test(filePath)) return [];

    return regexMatcher(
      "rb-grape-endpoint",
      [
        {
          regex: /^\s*(?:get|post|put|patch|delete)\s+:\w+/m,
          label: "Grape <verb> :name do",
        },
        {
          regex: /^\s*resource\s+:\w+/m,
          label: "resource :name do block",
        },
        { regex: /^\s*before\s+do\b/m, label: "before do — auth filter" },
        {
          regex: /\bdeclared\s*\(\s*params\s*\)/,
          label: "declared(params) — strong-params equivalent",
        },
      ],
      content,
    );
  },
};

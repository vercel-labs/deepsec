import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const rbRailsControllerMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "rb-rails-controller",
  description: "Rails controllers, routes, and action methods (gated on Rails)",
  filePatterns: [
    "**/app/controllers/**/*.rb",
    "**/config/routes.rb",
    "**/app/jobs/**/*.rb",
    "**/app/mailers/**/*.rb",
  ],
  requires: { tech: ["rails"] },
  examples: [
    `class UsersController < ApplicationController`,
    `class PostsController < BaseController`,
    `  before_action :authenticate_user!, only: [:show, :edit]`,
    `  skip_before_action :verify_authenticity_token`,
    `resources :articles`,
    `get "/health", to: "health#index"`,
    `post '/login', to: 'sessions#create'`,
    `match "/legacy", to: "legacy#show", via: [:get, :post]`,
    `params.require(:user).permit(:email, :name)`,
  ],
  match(content, filePath) {
    if (/\b(?:test|spec)\b/i.test(filePath)) return [];

    return regexMatcher(
      "rb-rails-controller",
      [
        {
          regex: /^\s*class\s+\w+Controller\s*<\s*\w*Controller\b/m,
          label: "Rails controller class",
        },
        { regex: /^\s*before_action\s+/m, label: "before_action callback" },
        {
          regex: /^\s*skip_before_action\s+/m,
          label: "skip_before_action (auth bypass — confirm intent)",
        },
        {
          regex: /^\s*resources\s+:\w+/m,
          label: "routes.rb resources :foo (CRUD)",
        },
        {
          regex: /^\s*(?:get|post|put|patch|delete|match)\s+['"][^'"]+['"]\s*,/m,
          label: "routes.rb verb registration",
        },
        { regex: /params\.require\s*\(/, label: "strong params boundary" },
      ],
      content,
    );
  },
};

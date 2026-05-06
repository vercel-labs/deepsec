import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const exPhoenixControllerMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "ex-phoenix-controller",
  description: "Phoenix controllers, routers, and LiveView modules (gated on Phoenix)",
  filePatterns: ["**/*.{ex,exs}"],
  requires: { tech: ["phoenix"] },
  examples: [
    `defmodule MyAppWeb.UserController do\n  use MyAppWeb, :controller\nend`,
    `  use MyAppWeb, :controller`,
    `  use MyAppWeb, :live_view`,
    `defmodule MyAppWeb.HomeLive do\n  use MyAppWeb, :live_view\nend`,
    `  get "/users", UserController, :index`,
    `  post "/users", UserController, :create`,
    `  live "/dashboard", DashboardLive, :index`,
    `  pipeline :api do\n    plug :accepts, ["json"]\n  end`,
    `    plug :authenticate_user`,
    `Repo.query!("SELECT * FROM users WHERE id = $1", [id])`,
  ],
  match(content, filePath) {
    if (/\/(test|tests)\//.test(filePath)) return [];

    return regexMatcher(
      "ex-phoenix-controller",
      [
        {
          regex: /^\s*use\s+\w+,\s+:controller\b/m,
          label: "use ..., :controller — Phoenix controller",
        },
        {
          regex: /^\s*use\s+\w+,\s+:live_view\b/m,
          label: "use ..., :live_view",
        },
        {
          regex: /^\s*(?:get|post|put|patch|delete|live)\s+"[^"]+"\s*,/m,
          label: "router pipeline verb",
        },
        {
          regex: /^\s*pipeline\s+:\w+\s+do\b/m,
          label: "pipeline :name do — auth scope",
        },
        { regex: /\bplug\s+:\w+/, label: "plug :name (auth/middleware wiring)" },
        { regex: /\bRepo\.query!?\s*\(/, label: "Repo.query — raw SQL surface" },
      ],
      content,
    );
  },
};

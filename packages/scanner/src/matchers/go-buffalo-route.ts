import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const goBuffaloRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "go-buffalo-route",
  description: "Buffalo app routes and resources (gated on buffalo)",
  filePatterns: ["**/*.go"],
  requires: { tech: ["buffalo"] },
  examples: [
    `app := buffalo.New(buffalo.Options{})`,
    `app.GET("/users", UsersList)`,
    `app.POST("/login", AuthCreate)`,
    `app.PUT("/items/{id}", ItemsUpdate)`,
    `app.PATCH("/profile", ProfilePatch)`,
    `app.DELETE("/items/{id}", ItemsDestroy)`,
    `app.Resource("/users", &UsersResource{})`,
    `id := c.Param("id")`,
    `req := c.Request()`,
    `if err := c.Bind(&u); err != nil {}`,
    `userID := c.Value("current_user_id")`,
  ],
  match(content, filePath) {
    if (/_test\.go$/.test(filePath)) return [];

    return regexMatcher(
      "go-buffalo-route",
      [
        {
          regex: /\bapp\.(?:GET|POST|PUT|PATCH|DELETE)\s*\(/,
          label: "Buffalo app.<VERB> registration",
        },
        { regex: /\bapp\.Resource\s*\(/, label: "app.Resource() (CRUD)" },
        { regex: /\bbuffalo\.New\s*\(/, label: "buffalo.New() init" },
        { regex: /\bc\.(?:Param|Request|Bind|Value)\b/, label: "buffalo.Context accessor" },
      ],
      content,
    );
  },
};

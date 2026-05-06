import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const goEchoRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "go-echo-route",
  description: "Echo (labstack) route registrations (gated on Echo)",
  filePatterns: ["**/*.go"],
  requires: { tech: ["echo"] },
  examples: [
    `e := echo.New()`,
    `e.GET("/users", listUsers)`,
    `app.POST("/login", login)`,
    `server.PUT("/items/:id", update)`,
    `g.PATCH("/profile", patch)`,
    `e.DELETE("/items/:id", delete)`,
    `e.Any("/proxy", proxy)`,
    `e.Match([]string{"GET", "POST"}, "/legacy", legacy)`,
    `api := e.Group("/api")`,
    `id := c.Param("id")`,
    `q := c.QueryParam("q")`,
    `name := c.FormValue("name")`,
    `if err := c.Bind(&u); err != nil {}`,
    `req := c.Request()`,
  ],
  match(content, filePath) {
    if (/_test\.go$/.test(filePath)) return [];

    return regexMatcher(
      "go-echo-route",
      [
        {
          regex: /\b(?:e|app|server|g)\.(?:GET|POST|PUT|PATCH|DELETE|Any|Match)\s*\(/,
          label: "Echo method registration",
        },
        { regex: /\b(?:e|app|server)\.Group\s*\(/, label: "Echo .Group (auth scope)" },
        { regex: /\becho\.New\s*\(\s*\)/, label: "echo.New() init" },
        {
          regex: /\bc\.(?:Param|QueryParam|FormValue|Bind|Request)\b/,
          label: "Request accessor (untrusted input)",
        },
      ],
      content,
    );
  },
};

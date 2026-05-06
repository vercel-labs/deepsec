import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const goGinRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "go-gin-route",
  description: "Gin route registrations and group middleware (gated on Gin)",
  filePatterns: ["**/*.go"],
  requires: { tech: ["gin"] },
  examples: [
    `r := gin.Default()`,
    `engine := gin.New()`,
    `r.GET("/users", listUsers)`,
    `router.POST("/login", loginHandler)`,
    `api.PUT("/items/:id", updateItem)`,
    `v1.PATCH("/profile", patchProfile)`,
    `engine.DELETE("/sessions/:id", logout)`,
    `r.Any("/proxy", proxyHandler)`,
    `r.Handle("OPTIONS", "/cors", corsHandler)`,
    `admin := r.Group("/admin")`,
    `id := c.Query("id")`,
    `name := c.Param("name")`,
    `email := c.PostForm("email")`,
    `auth := c.GetHeader("Authorization")`,
    `if err := c.ShouldBindJSON(&body); err != nil {}`,
  ],
  match(content, filePath) {
    if (/_test\.go$/.test(filePath)) return [];

    return regexMatcher(
      "go-gin-route",
      [
        {
          regex: /\b(?:r|router|engine|api|v\d+)\.(?:GET|POST|PUT|PATCH|DELETE|Any|Handle)\s*\(/,
          label: "Gin method registration",
        },
        { regex: /\.Group\s*\(/, label: "Gin .Group (middleware scope)" },
        { regex: /gin\.Default\s*\(\s*\)|gin\.New\s*\(\s*\)/, label: "Gin engine init" },
        {
          regex: /\bc\.(?:Query|Param|PostForm|GetHeader|ShouldBind\w*)\b/,
          label: "Request data accessor (untrusted input)",
        },
      ],
      content,
    );
  },
};

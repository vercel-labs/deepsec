import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const goFiberRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "go-fiber-route",
  description: "Fiber route registrations (gated on Fiber)",
  filePatterns: ["**/*.go"],
  requires: { tech: ["fiber"] },
  examples: [
    `app := fiber.New()`,
    `app.Get("/users", listUsers)`,
    `api.Post("/login", login)`,
    `router.Put("/items/:id", update)`,
    `g.Patch("/profile", patch)`,
    `app.Delete("/items/:id", deleteItem)`,
    `app.All("/proxy", proxy)`,
    `v1 := app.Group("/v1")`,
    `q := c.Query("q")`,
    `id := c.Params("id")`,
    `if err := c.BodyParser(&u); err != nil {}`,
    `body := c.Body()`,
    `auth := c.Get("Authorization")`,
    `name := c.FormValue("name")`,
    `session := c.Cookies("session")`,
  ],
  match(content, filePath) {
    if (/_test\.go$/.test(filePath)) return [];

    return regexMatcher(
      "go-fiber-route",
      [
        {
          regex: /\b(?:app|api|router|g)\.(?:Get|Post|Put|Patch|Delete|All)\s*\(/,
          label: "Fiber method registration",
        },
        { regex: /\bfiber\.New\s*\(/, label: "fiber.New() init" },
        { regex: /\.Group\s*\(/, label: "Fiber .Group (auth scope)" },
        {
          regex: /\bc\.(?:Query|Params|Body(?:Parser)?|Get|FormValue|Cookies)\b/,
          label: "Request accessor (untrusted input)",
        },
      ],
      content,
    );
  },
};

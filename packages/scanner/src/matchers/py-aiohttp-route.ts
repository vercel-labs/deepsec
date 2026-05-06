import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const pyAiohttpRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "py-aiohttp-route",
  description: "aiohttp route registrations (gated on aiohttp)",
  filePatterns: ["**/*.py"],
  requires: { tech: ["aiohttp"] },
  examples: [
    `app.router.add_get("/users", handler)`,
    `app.router.add_post("/login", login_handler)`,
    `app.router.add_put("/items/{id}", update_item)`,
    `app.router.add_route("GET", "/x", handle)`,
    `@routes.get("/health")`,
    `@routes.post('/submit')`,
    `   @routes.view("/items")`,
    `app = web.Application(middlewares=[auth_middleware])`,
    `data = await request.json()`,
    `q = request.query.get("q")`,
    `pk = request.match_info["id"]`,
  ],
  match(content, filePath) {
    if (/\b(?:tests?|migrations)\b/i.test(filePath)) return [];

    return regexMatcher(
      "py-aiohttp-route",
      [
        {
          regex: /\bapp\.router\.add_(?:get|post|put|patch|delete|route)\s*\(/,
          label: "app.router.add_*",
        },
        {
          regex: /^\s*@routes\.(?:get|post|put|patch|delete|view)\s*\(/m,
          label: "@routes.* decorator",
        },
        { regex: /\bweb\.Application\s*\(/, label: "web.Application() init" },
        { regex: /\brequest\.(?:query|match_info|json|post|read)\b/, label: "request accessor" },
      ],
      content,
    );
  },
};

import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const jsHonoRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "js-hono-route",
  description: "Hono route registrations — entry points (weak candidate, gated on Hono)",
  filePatterns: ["**/*.{ts,js,mjs}"],
  requires: { tech: ["hono"] },
  examples: [
    `const app = new Hono();`,
    `app.get("/users", (c) => c.json({}))`,
    `app.post('/login', async (c) => {})`,
    `app.put("/items/:id", handler);`,
    `app.delete("/x", handler)`,
    `app.use("*", authMiddleware);`,
    `router.all('/health', h)`,
    `c.req.query("page")`,
    `await c.req.json()`,
    `c.req.param("id")`,
    `await c.req.formData();`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    return regexMatcher(
      "js-hono-route",
      [
        {
          regex: /\b(?:app|router|hono)\.(?:get|post|put|patch|delete|options|all|use)\s*\(/,
          label: "Hono method/use registration",
        },
        { regex: /new\s+Hono\s*\(/, label: "new Hono() instantiation" },
        {
          regex: /\bc\.req\.(?:query|param|json|formData|text|valid)\b/,
          label: "Request data accessor",
        },
      ],
      content,
    );
  },
};

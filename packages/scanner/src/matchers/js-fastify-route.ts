import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const jsFastifyRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "js-fastify-route",
  description: "Fastify route registrations — entry points (weak candidate, gated on Fastify)",
  filePatterns: ["**/*.{ts,js,mjs,cjs}"],
  requires: { tech: ["fastify"] },
  examples: [
    `fastify.get("/", async () => "ok");`,
    `fastify.post('/users', handler)`,
    `app.put("/items/:id", async (req, reply) => {});`,
    `instance.register(authPlugin);`,
    `server.route({ method: "POST", url: "/x", handler })`,
    `app.route({ method: 'GET', url: '/y', handler });`,
    `fastify.addHook("preHandler", async (request, reply) => {});`,
    `app.addHook('onRequest', authHook)`,
    `instance.addHook("preValidation", validate);`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    return regexMatcher(
      "js-fastify-route",
      [
        {
          regex:
            /\b(?:fastify|instance|app|server)\.(?:get|post|put|patch|delete|head|options|route|register)\s*\(/,
          label: "fastify method/route/register call",
        },
        {
          regex: /\.route\s*\(\s*\{[\s\S]*?method\s*:/,
          label: "fastify .route({ method, ... }) form",
        },
        {
          regex: /addHook\s*\(\s*['"](?:onRequest|preHandler|preValidation)['"]/,
          label: "auth-relevant lifecycle hook",
        },
      ],
      content,
    );
  },
};

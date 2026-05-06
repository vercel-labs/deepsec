import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const jsKoaRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "js-koa-route",
  description: "Koa route registrations and middleware (gated on Koa)",
  filePatterns: ["**/*.{ts,js,mjs,cjs}"],
  requires: { tech: ["koa"] },
  examples: [
    `const app = new Koa();`,
    `router.get("/users", handler)`,
    `router.post('/login', handler);`,
    `router.put("/x", h)`,
    `router.del('/y', h)`,
    `app.use(authMiddleware)`,
    `import KoaRouter from "@koa/router";`,
    `const r = KoaRouter();`,
    `app.use(async (ctx, next) => { await next(); })`,
    `async (ctx) => ctx.body = {}`,
    `ctx.request.body`,
    `ctx.query.page`,
    `ctx.params.id`,
    `ctx.state.user`,
    `ctx.throw(401)`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    return regexMatcher(
      "js-koa-route",
      [
        {
          regex: /\b(?:router|app)\.(?:get|post|put|patch|del|delete|all|use)\s*\(/,
          label: "Koa router method registration",
        },
        { regex: /new\s+Koa\s*\(/, label: "new Koa() instantiation" },
        { regex: /\bKoaRouter\s*\(|@koa\/router/, label: "@koa/router import or factory" },
        { regex: /async\s*\(\s*ctx\s*[,)]/, label: "Koa middleware (ctx) signature" },
        { regex: /\bctx\.(?:request|query|params|state|throw)\b/, label: "ctx.* accessor" },
      ],
      content,
    );
  },
};

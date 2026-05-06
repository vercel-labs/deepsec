import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

/**
 * Express.js route registration and handler entry points. Wide-net by
 * design — every `.get/.post/.use(...)` is a public endpoint surface that
 * deserves an AI read.
 *
 * Gated on `tech: ["express"]` from `detectTech()` so it doesn't fire on
 * a random Node script that happens to have `app.get(...)` in it.
 */
export const jsExpressRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "js-express-route",
  description: "Express.js route registrations — entry points (weak candidate, gated on Express)",
  filePatterns: ["**/*.{ts,js,mjs,cjs,tsx}"],
  requires: { tech: ["express"] },
  examples: [
    `app.get("/users", (req, res) => res.json({}));`,
    `app.post('/login', async (req, res, next) => {})`,
    `app.put("/items/:id", handler);`,
    `app.delete("/x", handler)`,
    `app.all("*", catchAll)`,
    `router.use(authMiddleware);`,
    `router.get("/health", (req, res) => res.send("ok"))`,
    `const r = express.Router();`,
    `function handle(req, res, next) { res.send(""); }`,
    `const h = ( req , res , next ) => res.end();`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    return regexMatcher(
      "js-express-route",
      [
        {
          regex: /\b(?:app|router)\.(?:get|post|put|patch|delete|all|use)\s*\(/,
          label: "app/router method registration",
        },
        { regex: /express\.Router\s*\(/, label: "express.Router() factory" },
        {
          regex: /\(\s*req\s*,\s*res(?:\s*,\s*next)?\s*\)\s*=>/,
          label: "(req, res) handler signature",
        },
        {
          regex: /function\s+\w+\s*\(\s*req\s*,\s*res(?:\s*,\s*next)?\s*\)/,
          label: "function (req, res) handler",
        },
      ],
      content,
    );
  },
};

import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const pyBottleRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "py-bottle-route",
  description: "Bottle route decorators (gated on Bottle)",
  filePatterns: ["**/*.py"],
  requires: { tech: ["bottle"] },
  examples: [
    `@route("/")`,
    `@get("/users")`,
    `@post('/login')`,
    `@put("/items/<id>")`,
    `@delete("/items/<id>")`,
    `@patch("/items/<id>")`,
    `app = Bottle()`,
    `name = request.query.get("name")`,
    `data = request.json`,
    `f = request.forms.get("name")`,
  ],
  match(content, filePath) {
    if (/\b(?:tests?|migrations)\b/i.test(filePath)) return [];

    return regexMatcher(
      "py-bottle-route",
      [
        {
          regex: /^\s*@(?:route|get|post|put|patch|delete)\s*\(\s*['"][^'"]+['"]/m,
          label: "Bottle @route/@method decorator",
        },
        { regex: /\bBottle\s*\(\s*\)/, label: "Bottle() instance" },
        { regex: /\brequest\.(?:query|forms|json|cookies)\b/, label: "request accessor" },
      ],
      content,
    );
  },
};

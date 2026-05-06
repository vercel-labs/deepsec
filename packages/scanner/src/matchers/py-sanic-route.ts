import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const pySanicRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "py-sanic-route",
  description: "Sanic route handlers and Blueprints (gated on Sanic)",
  filePatterns: ["**/*.py"],
  requires: { tech: ["sanic"] },
  examples: [
    `@app.route("/")`,
    `@bp.route("/items", methods=["GET", "POST"])`,
    `@blueprint.route("/x")`,
    `@app.get("/health")`,
    `@app.post('/login')`,
    `@bp.put("/items/<id:int>")`,
    `@app.websocket("/ws")`,
    `app = Sanic("my-app")`,
    `data = request.json`,
    `name = request.args.get("name")`,
    `f = request.files.get("upload")`,
  ],
  match(content, filePath) {
    if (/\b(?:tests?|migrations)\b/i.test(filePath)) return [];

    return regexMatcher(
      "py-sanic-route",
      [
        {
          regex: /^\s*@(?:app|bp|blueprint)\.route\s*\(/m,
          label: "Sanic @app.route / @bp.route",
        },
        {
          regex: /^\s*@(?:app|bp)\.(?:get|post|put|patch|delete|head|options|websocket)\s*\(/m,
          label: "Sanic method-shortcut decorator",
        },
        { regex: /\bSanic\s*\(\s*['"][^'"]*['"]\s*\)/, label: "Sanic() instance" },
        { regex: /\brequest\.(?:args|json|form|files|headers)\b/, label: "request accessor" },
      ],
      content,
    );
  },
};

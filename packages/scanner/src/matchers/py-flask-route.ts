import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const pyFlaskRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "py-flask-route",
  description: "Flask route registrations — entry points (gated on Flask)",
  filePatterns: ["**/*.py"],
  requires: { tech: ["flask"] },
  examples: [
    `@app.route("/")`,
    `@bp.route("/items", methods=["GET", "POST"])`,
    `@blueprint.route("/x")`,
    `@api.route("/v1/users")`,
    `@app.get("/health")`,
    `@app.post("/login")`,
    `@bp.put("/items/<int:id>")`,
    `bp = Blueprint("api", __name__, url_prefix="/api")`,
    `return render_template_string(template, name=name)`,
  ],
  match(content, filePath) {
    if (/\b(?:tests?|migrations)\b/i.test(filePath)) return [];

    return regexMatcher(
      "py-flask-route",
      [
        {
          regex: /^\s*@(?:app|bp|blueprint|api)\.route\s*\(/m,
          label: "Flask @app.route / blueprint.route",
        },
        {
          regex: /^\s*@(?:app|bp)\.(?:get|post|put|patch|delete)\s*\(/m,
          label: "Flask method-shortcut decorator",
        },
        { regex: /\bBlueprint\s*\(/, label: "Blueprint(...) registration" },
        { regex: /\brender_template_string\s*\(/, label: "render_template_string (SSTI sink)" },
      ],
      content,
    );
  },
};

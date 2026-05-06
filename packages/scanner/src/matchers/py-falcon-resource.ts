import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const pyFalconResourceMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "py-falcon-resource",
  description: "Falcon resource classes with on_<method> handlers (gated on Falcon)",
  filePatterns: ["**/*.py"],
  requires: { tech: ["falcon"] },
  examples: [
    `    def on_get(self, req, resp):`,
    `    def on_post(self, req, resp):`,
    `    def on_put(self, req, resp, id):`,
    `    def on_delete(self, req, resp, id):`,
    `    def on_patch(self, req, resp):`,
    `app = falcon.App()`,
    `api = falcon.API()`,
    `app.add_route("/users", UserResource())`,
    `name = req.params.get("name")`,
    `data = req.media`,
    `q = req.get_param("q")`,
  ],
  match(content, filePath) {
    if (/\b(?:tests?|migrations)\b/i.test(filePath)) return [];

    return regexMatcher(
      "py-falcon-resource",
      [
        {
          regex: /^\s*def\s+on_(get|post|put|patch|delete|head|options)\s*\(\s*self\b/m,
          label: "on_<method>(self, req, resp) handler",
        },
        { regex: /\bfalcon\.App\s*\(|\bfalcon\.API\s*\(/, label: "falcon.App/API instance" },
        { regex: /\.add_route\s*\(\s*['"][^'"]+['"]/, label: "app.add_route() registration" },
        { regex: /\breq\.(?:params|media|context|get_param)\b/, label: "req.* accessor" },
      ],
      content,
    );
  },
};

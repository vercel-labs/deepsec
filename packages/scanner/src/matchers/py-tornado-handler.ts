import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const pyTornadoHandlerMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "py-tornado-handler",
  description: "Tornado RequestHandler subclasses and routing (gated on Tornado)",
  filePatterns: ["**/*.py"],
  requires: { tech: ["tornado"] },
  examples: [
    `class MainHandler(RequestHandler):`,
    `class UserHandler(tornado.web.RequestHandler):`,
    `    def get(self, user_id):`,
    `    def post(self):`,
    `    def put(self, id):`,
    `    def delete(self, id):`,
    `app = Application([(r"/", MainHandler), (r"/users/(.*)", UserHandler)])`,
    `    @tornado.web.authenticated`,
  ],
  match(content, filePath) {
    if (/\b(?:tests?|migrations)\b/i.test(filePath)) return [];

    return regexMatcher(
      "py-tornado-handler",
      [
        {
          regex: /^class\s+\w+\s*\(\s*(?:tornado\.web\.)?RequestHandler\s*\)/m,
          label: "RequestHandler subclass",
        },
        {
          regex: /^\s*def\s+(get|post|put|patch|delete|head|options)\s*\(\s*self\b/m,
          label: "method handler",
        },
        { regex: /Application\s*\(\s*\[/, label: "Application([(...handler...)])" },
        { regex: /@tornado\.web\.authenticated\b/, label: "@authenticated decorator" },
      ],
      content,
    );
  },
};

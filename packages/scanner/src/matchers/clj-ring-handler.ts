import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const cljRingHandlerMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "clj-ring-handler",
  description: "Clojure Ring/Compojure routes and handlers (gated on Clojure)",
  filePatterns: ["**/*.{clj,cljs,cljc}"],
  requires: { tech: ["clojure"] },
  examples: [
    `(defroutes app-routes\n  (GET "/" [] "Hello"))`,
    `(defroutes api\n  (POST "/users" req (create-user req)))`,
    `  (GET "/users/:id" [id] (get-user id))`,
    `  (PUT "/users/:id" [id :as req] (update-user id req))`,
    `  (DELETE "/users/:id" [id] (delete-user id))`,
    `  (PATCH "/users/:id" [id :as req] (patch id req))`,
    `  (ANY "/healthz" [] "ok")`,
    `(defn handler [request] (response "hi"))`,
    `(defn login [req] (-> req :params :user))`,
    `(-> handler\n    (wrap-authentication backend)\n    (wrap-authorization backend))`,
    `(wrap-cors handler)`,
    `(wrap-csrf handler)`,
  ],
  match(content, filePath) {
    if (/\/(test|spec)\//.test(filePath)) return [];

    return regexMatcher(
      "clj-ring-handler",
      [
        {
          regex: /\bdefroutes\b/,
          label: "defroutes Compojure declaration",
        },
        {
          regex: /\((?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|ANY)\s+"[^"]+"/,
          label: "Compojure route verb",
        },
        {
          regex: /\bdefn\s+\w+\s+\[\s*(?:request|req)\b/,
          label: "Ring handler fn (request-shape arg)",
        },
        { regex: /\bwrap-(?:authentication|authorization|cors|csrf)\b/, label: "Ring middleware" },
      ],
      content,
    );
  },
};

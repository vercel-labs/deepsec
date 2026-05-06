import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const goHttpHandlerMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "go-http-handler",
  description: "Go HTTP handler functions — entry points for investigation (weak candidate)",
  filePatterns: ["**/*.go"],
  requires: { tech: ["go"] },
  examples: [
    `http.HandleFunc("/users", usersHandler)`,
    `http.Handle("/api/", apiHandler)`,
    `mux.HandleFunc("/login", loginHandler)`,
    `mux.Handle("/static/", fs)`,
    `r.GET("/users/:id", getUser)`,
    `router.POST("/items", createItem)`,
    `app.PUT("/users/:id", updateUser)`,
    `e.DELETE("/items/:id", deleteItem)`,
    `func usersHandler(w http.ResponseWriter, r *http.Request) {`,
    `func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {`,
  ],
  match(content, filePath) {
    if (/_test\.go$/.test(filePath)) return [];

    return regexMatcher(
      "go-http-handler",
      [
        { regex: /http\.HandleFunc\s*\(/, label: "http.HandleFunc registration" },
        { regex: /http\.Handle\s*\(/, label: "http.Handle registration" },
        { regex: /mux\.Handle(Func)?\s*\(/, label: "mux handler registration" },
        { regex: /\.GET\s*\(|\.POST\s*\(|\.PUT\s*\(|\.DELETE\s*\(/, label: "HTTP method handler" },
        {
          regex: /func\s+\w+\s*\(\s*w\s+http\.ResponseWriter.*r\s+\*http\.Request/,
          label: "HTTP handler function signature",
        },
        { regex: /ServeHTTP\s*\(/, label: "ServeHTTP implementation" },
      ],
      content,
    );
  },
};

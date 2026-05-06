import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const goGorillaRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "go-gorilla-route",
  description: "Gorilla mux router registrations (gated on gorilla)",
  filePatterns: ["**/*.go"],
  requires: { tech: ["gorilla"] },
  examples: [
    `r := mux.NewRouter()`,
    `r.HandleFunc("/users", listUsers)`,
    `router.HandleFunc("/login", login).Methods("POST")`,
    `s.HandleFunc("/items/{id}", updateItem).Methods("PUT")`,
    `r.HandleFunc("/items/{id}", patchItem).Methods("PATCH")`,
    `r.HandleFunc("/items/{id}", deleteItem).Methods("DELETE")`,
    `api := r.PathPrefix("/api").Subrouter()`,
    `vars := mux.Vars(r)`,
  ],
  match(content, filePath) {
    if (/_test\.go$/.test(filePath)) return [];

    return regexMatcher(
      "go-gorilla-route",
      [
        {
          regex: /\bmux\.NewRouter\s*\(\s*\)/,
          label: "mux.NewRouter() init",
        },
        {
          regex: /\.HandleFunc\s*\(\s*"[^"]+"\s*,/,
          label: "router.HandleFunc('/path', handler)",
        },
        { regex: /\.Methods\s*\(\s*"(?:GET|POST|PUT|PATCH|DELETE)"/, label: ".Methods('VERB')" },
        { regex: /\.PathPrefix\s*\(/, label: ".PathPrefix() subroute scope" },
        { regex: /\bmux\.Vars\s*\(\s*r\s*\)/, label: "mux.Vars(r) (untrusted input)" },
      ],
      content,
    );
  },
};

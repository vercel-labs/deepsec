import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const goChiRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "go-chi-route",
  description: "Chi router registrations and route groups (gated on Chi)",
  filePatterns: ["**/*.go"],
  requires: { tech: ["chi"] },
  examples: [
    `r := chi.NewRouter()`,
    `r.Get("/users", listUsers)`,
    `router.Post("/login", login)`,
    `api.Put("/items/{id}", update)`,
    `r.Patch("/profile", patch)`,
    `r.Delete("/items/{id}", deleteItem)`,
    `r.Method("OPTIONS", "/cors", corsHandler)`,
    `r.Handle("/static/*", fileServer)`,
    `r.HandleFunc("/health", healthHandler)`,
    `r.Route("/admin", func(r chi.Router) {})`,
    `r.Group(func(r chi.Router) {})`,
    `r.Mount("/api", apiRouter())`,
    `id := chi.URLParam(r, "id")`,
  ],
  match(content, filePath) {
    if (/_test\.go$/.test(filePath)) return [];

    return regexMatcher(
      "go-chi-route",
      [
        {
          regex: /\b(?:r|router|api)\.(?:Get|Post|Put|Patch|Delete|Method|Handle|HandleFunc)\s*\(/,
          label: "Chi method registration",
        },
        { regex: /\bchi\.NewRouter\s*\(\s*\)/, label: "chi.NewRouter() init" },
        { regex: /\.Route\s*\(/, label: "Chi .Route (subroute scope)" },
        { regex: /\.Group\s*\(/, label: "Chi .Group (middleware scope)" },
        { regex: /\.Mount\s*\(/, label: "Chi .Mount (subrouter — middleware inheritance gotcha)" },
        { regex: /\bchi\.URLParam\s*\(/, label: "chi.URLParam (untrusted input)" },
      ],
      content,
    );
  },
};

import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const goSsrfMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "go-ssrf",
  description: "Go HTTP requests with string-concatenated or formatted URLs — SSRF risk",
  filePatterns: ["**/*.go"],
  requires: { tech: ["go"] },
  examples: [
    `resp, err := http.Get(baseURL + path)`,
    `resp, err := http.Post(host + "/api", "application/json", body)`,
    `resp, err := http.Head("https://" + target)`,
    `req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/api", host), nil)`,
    `req, err := http.NewRequest("POST", baseURL + path, body)`,
    `u, err := url.Parse(scheme + "://" + host)`,
    `endpoint := fmt.Sprintf("https://api.example.com/users/%s", userID)`,
  ],
  match(content, filePath) {
    if (/_test\.go$/.test(filePath)) return [];

    return regexMatcher(
      "go-ssrf",
      [
        { regex: /http\.(Get|Post|Head)\s*\(.*\+/, label: "http.Get/Post with string concat URL" },
        {
          regex: /http\.NewRequest\s*\(.*fmt\.Sprintf/,
          label: "http.NewRequest with formatted URL",
        },
        { regex: /http\.NewRequest\s*\(.*\+/, label: "http.NewRequest with concatenated URL" },
        { regex: /url\.Parse\s*\(.*\+/, label: "url.Parse with concatenated string" },
        { regex: /fmt\.Sprintf\s*\(\s*"https?:\/\//, label: "URL built via fmt.Sprintf" },
      ],
      content,
    );
  },
};

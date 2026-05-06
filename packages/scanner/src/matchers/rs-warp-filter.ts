import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const rsWarpFilterMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "rs-warp-filter",
  description: "Warp filter compositions (gated on Warp)",
  filePatterns: ["**/*.rs"],
  requires: { tech: ["warp"] },
  examples: [
    `let route = warp::path!("hello" / String);`,
    `warp::path!("api" / "v1" / "users")`,
    `let users = warp::get();`,
    `warp::post()`,
    `warp::delete()`,
    `.and_then(handle_request)`,
    `.and(warp::filters::body::json())`,
    `let api = warp::path!("login").and(warp::post()).and(warp::filters::body::json()).and_then(login);`,
  ],
  match(content, filePath) {
    if (/\/(tests|examples)\//.test(filePath)) return [];

    return regexMatcher(
      "rs-warp-filter",
      [
        {
          regex: /\bwarp::path!\s*\(/,
          label: "warp::path!() filter",
        },
        { regex: /\bwarp::(?:get|post|put|patch|delete)\s*\(\s*\)/, label: "warp::<verb>()" },
        { regex: /\.and_then\s*\(/, label: ".and_then(handler)" },
        { regex: /\bwarp::filters::body::json\s*\(/, label: "json body extractor" },
      ],
      content,
    );
  },
};

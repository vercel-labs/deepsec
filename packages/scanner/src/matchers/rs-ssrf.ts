import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const rsSsrfMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "rs-ssrf",
  description:
    "Rust HTTP clients (reqwest, ureq, hyper, surf, isahc) issuing requests against formatted or concatenated URLs — SSRF risk",
  filePatterns: ["**/*.rs"],
  requires: { tech: ["rust"] },
  examples: [
    `let resp = reqwest::get(&format!("https://{}/api", host)).await?;`,
    `let resp = client.post(&format!("{}/users/{}", base_url, id)).send().await?;`,
    `let body = ureq::get(&(base_url.to_owned() + path)).call()?;`,
    `let url = Url::parse(&format!("https://{}/v1", target))?;`,
    `let req = Request::builder().uri(&format!("https://{}/api", host)).body(())?;`,
    `let resp = surf::get(base.to_string() + path).await?;`,
  ],
  match(content, filePath) {
    if (/\/(tests|examples|benches)\//.test(filePath)) return [];

    return regexMatcher(
      "rs-ssrf",
      [
        {
          regex:
            /\b(?:reqwest|ureq|surf|isahc)::(?:get|post|put|patch|delete|head)\s*\(\s*&?format!\s*\(/,
          label: "http client verb with format! URL",
        },
        {
          regex: /\.(?:get|post|put|patch|delete|head)\s*\(\s*&?format!\s*\(/,
          label: "client.verb(&format!(...))",
        },
        {
          regex: /\b(?:reqwest|ureq|surf|isahc)::(?:get|post|put|patch|delete|head)\s*\(.*?\+\s*\w/,
          label: "http client verb with concatenated URL",
        },
        {
          regex: /\.(?:get|post|put|patch|delete|head)\s*\(.*?\+\s*\w/,
          label: "client.verb(... + path)",
        },
        {
          regex: /\bUrl::parse\s*\(\s*&?format!\s*\(/,
          label: "Url::parse(&format!(...))",
        },
        {
          regex: /\bRequest::builder\s*\(\s*\)\s*\.uri\s*\(\s*&?format!\s*\(/,
          label: "Request::builder().uri(&format!(...))",
        },
        {
          regex: /format!\s*\(\s*"https?:\/\//,
          label: 'URL built via format!("http...")',
        },
      ],
      content,
    );
  },
};

import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const gcpCloudFunctionMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "gcp-cloud-function",
  description: "GCP Cloud Functions handlers (gated on gcp-cloud-functions)",
  filePatterns: ["**/*.{ts,js,mjs,cjs,py,go}"],
  requires: { tech: ["gcp-cloud-functions"] },
  examples: [
    `functions.http('helloHttp', (req, res) => { res.send("hi") })`,
    `functions.http("api", async (req, res) => { res.json({}) })`,
    `functions.cloudEvent('myEvent', (event) => {})`,
    `functions.cloudEvent("pubsubHandler", handler)`,
    `@functions_framework.http\ndef hello_http(request):\n    return "Hello"`,
    `functions.HTTP("HelloHTTP", helloHTTP)`,
    `const auth = req.headers.authorization`,
    `const t = req.get('Authorization')`,
    `const t = req.get("Authorization")`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    return regexMatcher(
      "gcp-cloud-function",
      [
        {
          regex: /\bfunctions\.http\s*\(\s*['"][^'"]+['"]\s*,/,
          label: "functions.http('name', handler) — HTTP function",
        },
        {
          regex: /\bfunctions\.cloudEvent\s*\(/,
          label: "functions.cloudEvent('name', handler) — event function",
        },
        {
          regex: /^\s*@functions_framework\.http\b/m,
          label: "@functions_framework.http (Python)",
        },
        {
          regex: /\bfunctions\.HTTP\s*\(\s*"[^"]+"\s*,/,
          label: "functions.HTTP() (Go) registration",
        },
        {
          regex: /\breq\.(?:headers\.authorization|get\(['"]Authorization)/,
          label: "Authorization header use",
        },
      ],
      content,
    );
  },
};

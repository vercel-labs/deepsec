import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

// Tokens that mark an argument as originating from request/user input.
const USER_INPUT_TOKEN = String.raw`(?:req\.|request\.|params\.|query\.|body\.|parsed\.|input\.|ctx\.|payload\.|searchParams|nextUrl|formData|headers\(\)|cookies\(\))`;

export const ssrfMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "ssrf",
  description: "HTTP requests with dynamic/user-controlled URLs",
  filePatterns: ["**/*.{ts,tsx,js,jsx}"],
  examples: [
    `fetch(req.body.url);`,
    `fetch(query.target);`,
    `fetch(searchParams.get('u'));`,
    `fetch(input.url);`,
    `axios.get(req.body.endpoint);`,
    `axios.post(params.url, data);`,
    `axios(query.target);`,
    `got(body.url);`,
    `ky(payload.url);`,
    `superagent(ctx.url);`,
    `https.get(req.query.target);`,
    "https.request(`https://api/${req.body.host}`);",
    `page.goto(req.body.url);`,
    `browser.goto(params.target);`,
    `page.setContent(req.body.html);`,
    `fetch(headers().get('x-target'));`,
    `fetch(cookies().get('redirect')?.value);`,
    `axios.post(formData.get('url'));`,
    `new URL(req.query.target);`,
    `new URL(nextUrl.searchParams.get('href'));`,
    "fetch(`${userBase}/items`);",
    "const target = `https://${req.body.host}`;",
    `const url = "http://" + req.query.host;`,
    `const targetUrl = req.query.url;`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    const matches = regexMatcher(
      "ssrf",
      [
        {
          regex: new RegExp(String.raw`fetch\s*\(\s*${USER_INPUT_TOKEN}`),
          label: "fetch with request-derived URL",
        },
        {
          regex: new RegExp(
            String.raw`axios\.(get|post|put|delete|patch|request)\s*\(\s*${USER_INPUT_TOKEN}`,
          ),
          label: "axios with request-derived URL",
        },
        {
          regex: new RegExp(String.raw`\b(axios|got|ky|superagent)\s*\(\s*${USER_INPUT_TOKEN}`),
          label: "HTTP client call with request-derived URL",
        },
        {
          regex: new RegExp(String.raw`https?\.(get|request)\s*\(\s*${USER_INPUT_TOKEN}`),
          label: "http(s).get/request with request-derived URL",
        },
        {
          regex: new RegExp(
            String.raw`\b(page|browser)\.(goto|setContent)\s*\(\s*${USER_INPUT_TOKEN}`,
          ),
          label: "browser navigation with request-derived URL",
        },
        { regex: /https?\.request\s*\(\s*`[^`]*\$\{/, label: "http.request with interpolated URL" },
        {
          regex: new RegExp(String.raw`new\s+URL\s*\(\s*${USER_INPUT_TOKEN}`),
          label: "new URL from request data",
        },
        {
          regex:
            /(?:const|let|var)\s+\w*[uU]rl\w*\s*=\s*[^;\n]*\b(?:req|request|params|query|body|searchParams|nextUrl|input)\b/,
          label: "URL-named variable assigned from request data",
        },
      ],
      content,
    );

    // String-built URLs are the strongest SSRF signal — they fire even
    // when the sink call lives on a different line than the URL is
    // constructed. Skip cases built from a constant/env-configured base.
    const lines = content.split("\n");
    const constantBaseUrls = /VERCEL_API_URL|API_BASE|API_URL|INTERNAL_URL|process\.env\.\w+_URL/;
    const stringBuiltUrlRules = [
      {
        regex: /fetch\s*\(\s*`[^`]*\$\{/,
        label: "fetch with interpolated URL (non-constant base)",
      },
      { regex: /https?:\/\/[^`]*\$\{/, label: "string-built URL via template interpolation" },
      { regex: /["']https?:\/\/["']\s*\+/, label: "string-built URL via concatenation" },
    ];
    for (let i = 0; i < lines.length; i++) {
      if (constantBaseUrls.test(lines[i])) continue;
      for (const { regex, label } of stringBuiltUrlRules) {
        if (!regex.test(lines[i])) continue;
        const start = Math.max(0, i - 2);
        const end = Math.min(lines.length, i + 3);
        matches.push({
          vulnSlug: "ssrf",
          lineNumbers: [i + 1],
          snippet: lines.slice(start, end).join("\n"),
          matchedPattern: label,
        });
      }
    }

    return matches;
  },
};

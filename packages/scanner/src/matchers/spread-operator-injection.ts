import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const spreadOperatorInjectionMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "spread-operator-injection",
  description:
    "Object spread of user input into payloads — prototype pollution or key injection risk",
  filePatterns: ["**/*.{ts,tsx,js,jsx}"],
  examples: [
    `const payload = { ...req.body, createdAt: new Date() };`,
    `await db.user.create({ data: { ...request.body } });`,
    `const merged = { ...parsed.body };`,
    `return { ...parsed.query, page: 1 };`,
    `const next = { ...searchParams };`,
    `function build(params) { return { ...params, role: "user" }; }`,
    `const out = { ...query };`,
    `Object.assign({}, req, { id: 1 })`,
    `Object.assign({ }, body, { extra: true })`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    return regexMatcher(
      "spread-operator-injection",
      [
        { regex: /\.\.\.(req\.body|request\.body)/, label: "Spread of req.body" },
        { regex: /\.\.\.(parsed\.body|parsed\.query)/, label: "Spread of parsed input" },
        { regex: /\.\.\.searchParams/, label: "Spread of searchParams" },
        { regex: /\.\.\.(params|query)\b/, label: "Spread of params/query" },
        {
          regex: /Object\.assign\s*\(\s*\{?\s*\}\s*,\s*(req|body|params|query)/,
          label: "Object.assign from user input",
        },
      ],
      content,
    );
  },
};

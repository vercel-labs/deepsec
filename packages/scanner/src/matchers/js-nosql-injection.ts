import type { MatcherPlugin } from "@deepsec/core";
import { regexMatcher } from "./utils.js";

/**
 * NoSQL injection — Mongoose / MongoDB driver raw operators and unsafe
 * shapes. The flagged forms:
 *
 *   - `$where` with concatenation, function bodies, or template-literal
 *     interpolation (server-side JS execution; equivalent to eval).
 *   - `find(JSON.parse(req.<...>))` — passing raw user JSON as a query
 *     allows operator injection (e.g. `{ "$ne": null }` to bypass auth).
 *   - `aggregate([{ ..., $where: ... }])` — `$where` inside a pipeline.
 *   - `new RegExp(req.<...>)` — regex from user input is both ReDoS and a
 *     query-shape injection vector.
 *   - `findOne({ field: req.body.email })` — passing the whole request
 *     property without coercion lets `{ $ne: null }` slip through.
 */
export const jsNosqlInjectionMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "js-nosql-injection",
  description:
    "NoSQL injection — Mongoose / MongoDB driver raw operators ($where, JSON.parse(input)) and unsafe aggregations",
  filePatterns: ["**/*.{ts,tsx,js,jsx,mjs,cjs}"],
  examples: [
    `User.find({ $where: "this.name == '" + name + "'" })`,
    `db.collection.find({ $where: \`this.x == '\${input}'\` })`,
    `Model.find({ $where: function() { return this.x == y; } })`,
    `Model.find(JSON.parse(req.body.filter))`,
    `coll.aggregate([{ $match: { $where: "this.score > " + score } }])`,
    `User.find({ name: new RegExp(req.query.q) })`,
    `Model.findOne({ email: req.body.email })`,
    `User.find({ username: req.query.username })`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)$/.test(filePath)) return [];
    if (/\.d\.ts$/.test(filePath)) return [];

    return regexMatcher(
      "js-nosql-injection",
      [
        // $where with string concat / function body / template-literal interp.
        // The concat shape allows ' or " inside the inner string (the closing
        // quote of the $where value is matched by the [`"'] in the lookahead).
        {
          regex:
            /\$where\s*:\s*"[^"]{0,200}"\s*\+|\$where\s*:\s*'[^']{0,200}'\s*\+|\$where\s*:\s*function|\$where\s*:\s*`[^`]{0,200}\$\{/,
          label:
            "MongoDB $where with concatenation/function/template — server-side JS execution, injection",
        },
        // .find(JSON.parse(req.<...>))
        {
          regex: /\.find\s*\(\s*JSON\.parse\s*\(\s*req\./,
          label: "find(JSON.parse(req.*)) — operator injection via raw user JSON",
        },
        // aggregate pipeline containing $where
        {
          regex: /\.aggregate\s*\(\s*\[?\s*\{[^}]{0,400}\$where/,
          label: "MongoDB aggregate() pipeline using $where — server-side JS execution",
        },
        // new RegExp(req.<...>)
        {
          regex: /\bnew\s+RegExp\s*\(\s*req\./,
          label: "new RegExp from req.* — ReDoS and NoSQL query-shape injection",
        },
        // findOne / find with a single field bound to req.<obj>.<prop>.
        // `\.find(?:One)?` matches both `.find(...)` and `.findOne(...)` —
        // an earlier draft used `\.findOne?` which only matches `.findOn`
        // or `.findOne` and silently skipped plain `.find()`.
        {
          regex: /\.find(?:One)?\s*\(\s*\{[^}]{0,200}:\s*req\.\w+\.\w+/,
          label:
            "find/findOne with untyped req.* value — coerce to string or operator injection (e.g. { $ne: null })",
        },
      ],
      content,
    );
  },
};

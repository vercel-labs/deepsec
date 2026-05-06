import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

/**
 * PyMongo / Motor NoSQL injection candidates.
 *
 * The `$where` operator evaluates a JavaScript expression server-side;
 * building it from f-strings or untrusted input is a code-execution
 * vector, not just a query-injection one. Aggregation pipelines that
 * splice `$where` from user input have the same problem. Loading raw
 * JSON from a request body straight into a Mongo query lets the client
 * smuggle operators (`$ne`, `$gt`, `$where`) the server didn't intend
 * to expose, and compiling regexes from request input is a classic
 * ReDoS / injection footgun.
 */
export const pyNosqlInjectionMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "py-nosql-injection",
  description:
    "PyMongo / Motor NoSQL injection — \\$where with f-strings, raw aggregation pipelines fed user input",
  filePatterns: ["**/*.py"],
  requires: { tech: ["python"] },
  examples: [
    `coll.find({"$where": f"this.x == '{name}'"})`,
    `db.users.find({'$where': f"this.id == {uid}"})`,
    `Model.objects(__raw__={"$where": f"this.x == '{q}'"})`,
    `coll.aggregate([{"$match": {"$where": f"this.score > {score}"}}])`,
    `coll.find({"name": {"$regex": request.args.get("q")}})`,
    `q = json.loads(request.json["filter"])`,
  ],
  match(content, filePath) {
    if (/\b(?:tests?|migrations)\b/i.test(filePath)) return [];

    return regexMatcher(
      "py-nosql-injection",
      [
        {
          regex: /\$where['"]\s*:\s*f['"]/,
          label: '"$where" key bound to f-string — server-side JS injection',
        },
        {
          regex: /'\$where'\s*:\s*f['"]/,
          label: "'$where' key bound to f-string — server-side JS injection",
        },
        {
          regex: /\.find\s*\(\s*\{[^}]{0,200}\$where/,
          label: ".find() query containing $where — verify operands aren't user-controlled",
        },
        {
          regex: /\.aggregate\s*\(\s*\[?\s*\{[^}]{0,400}\$where/,
          label: ".aggregate() pipeline containing $where — verify operands aren't user-controlled",
        },
        {
          regex: /\bjson\.loads\s*\(\s*request\.(?:args|json|data)/,
          label: "json.loads on request body — operator smuggling into Mongo queries",
        },
        {
          regex: /\bre\.compile\s*\(\s*request\./,
          label: "re.compile on request input — ReDoS / regex injection",
        },
        {
          regex: /\$regex['"]\s*:\s*request\.|'\$regex'\s*:\s*request\./,
          label: "$regex bound to request input — ReDoS / regex injection in MongoDB query",
        },
      ],
      content,
    );
  },
};

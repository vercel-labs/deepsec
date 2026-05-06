import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const objectInjectionMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "object-injection",
  description: "Prototype pollution via Object.assign/merge/defaults with user input",
  filePatterns: ["**/*.{ts,tsx,js,jsx}"],
  examples: [
    `const merged = Object.assign({}, req.body);`,
    `Object.assign({ }, params, defaults);`,
    `const out = _.merge({}, defaults, req.body);`,
    `lodash.merge(target, source);`,
    `import { merge } from "lodash/merge";
const out = lodash.merge(target, userInput);`,
    `deepMerge(target, payload);`,
    `_.defaultsDeep(opts, userOpts);`,
    `defaultsDeep(target, source);`,
    `obj[req.query] = "value";`,
    `body[userKey] = req.params.id;`,
    `params[someKey] = 1;`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    return regexMatcher(
      "object-injection",
      [
        {
          regex: /Object\.assign\s*\(\s*\{\s*\}\s*,\s*(req|body|params|query)/,
          label: "Object.assign from user input",
        },
        {
          regex: /lodash[\w./]{0,20}merge\s*\(|_\.merge\s*\(|deepMerge\s*\(/,
          label: "Deep merge (prototype pollution risk)",
        },
        {
          regex: /_\.defaultsDeep\s*\(|defaultsDeep\s*\(/,
          label: "defaultsDeep (prototype pollution)",
        },
        {
          regex: /\[req\.\w+\]|body\[[^\]]{0,80}\]\s*=|params\[[^\]]{0,80}\]\s*=/,
          label: "Dynamic property assignment from user input",
        },
      ],
      content,
    );
  },
};

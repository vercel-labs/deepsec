import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const jsSolidstartActionMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "js-solidstart-action",
  description: "SolidStart server actions and cached server functions (gated on SolidStart)",
  filePatterns: ["**/*.{ts,tsx,js,jsx}"],
  requires: { tech: ["solidstart"] },
  examples: [
    `export const updateUser = action(async (form: FormData) => {})`,
    `const getUsers = cache(async (id: string) => {}, "users")`,
    `const search = query(async (q: string) => {}, "search")`,
    `return"use server";`,
    `x'use server';`,
    `const create = action$(async (data) => { return data })`,
    `const me = server$(async () => ({ id: 1 }))`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    return regexMatcher(
      "js-solidstart-action",
      [
        {
          regex: /\b(?:action|cache|query)\s*\(\s*async\s*\(/,
          label: "action/cache/query factory",
        },
        { regex: /\b['"]use server['"]\s*;?/, label: "'use server' directive (publicly callable)" },
        { regex: /\baction\$\s*\(|\bserver\$\s*\(/, label: "action$ / server$ helper" },
      ],
      content,
    );
  },
};

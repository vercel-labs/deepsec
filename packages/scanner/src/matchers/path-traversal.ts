import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const pathTraversalMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "path-traversal",
  description: "File system operations with user-controlled paths",
  filePatterns: ["**/*.{ts,tsx,js,jsx}"],
  examples: [
    `readFile(req.body.path, cb);`,
    `readFileSync(params.file);`,
    "readFile(`${root}/${req.body.path}`);",
    `writeFile(req.body.target, data, cb);`,
    "writeFileSync(`/data/${request.body.name}`, blob);",
    `path.join(root, req.body.subdir);`,
    `path.resolve(base, params.dir);`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    // Only flag when the interpolated variable looks user-controlled
    const _userInputPattern =
      /req\.|request\.|params\.|query\.|body\.|parsed\.|searchParams|\.input\b/;

    return regexMatcher(
      "path-traversal",
      [
        {
          regex: /readFile(Sync)?\s*\(\s*(req\.|request\.|params\.|query\.|body\.|parsed\.)/,
          label: "readFile with request-derived path",
        },
        {
          regex: /readFile(Sync)?\s*\(\s*`[^`]*(req\.|request\.|params\.|query\.|body\.)/,
          label: "readFile with request-derived interpolation",
        },
        {
          regex: /writeFile(Sync)?\s*\(\s*(req\.|request\.|params\.|query\.|body\.|parsed\.)/,
          label: "writeFile with request-derived path",
        },
        {
          regex: /writeFile(Sync)?\s*\(\s*`[^`]*(req\.|request\.|params\.|query\.|body\.)/,
          label: "writeFile with request-derived interpolation",
        },
        {
          regex: /path\.join\s*\([^)]*\b(req\.|request\.|params\.|query\.|body\.|parsed\.)/,
          label: "path.join with request-derived input",
        },
        {
          regex: /path\.resolve\s*\([^)]*\b(req\.|request\.|params\.|query\.|body\.|parsed\.)/,
          label: "path.resolve with request-derived input",
        },
      ],
      content,
    );
  },
};

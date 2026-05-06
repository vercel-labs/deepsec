import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const rceMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "rce",
  description: "exec, spawn, eval, Function constructor with potential user input",
  filePatterns: ["**/*.{ts,tsx,js,jsx}"],
  examples: [
    `child_process.exec(cmd);`,
    `exec(\`ls \${dir}\`);`,
    `execSync("whoami");`,
    `spawn("sh", ["-c", cmd]);`,
    `spawnSync("git", ["status"]);`,
    `eval(userInput);`,
    `new Function("return " + body)();`,
    `const cp = require("child_process");`,
    `import { exec } from "child_process";`,
    `vm.runInNewContext(code, ctx);`,
    `vm.runInThisContext(snippet);`,
  ],
  match(content, _filePath) {
    return regexMatcher(
      "rce",
      [
        { regex: /child_process.*exec\s*\(/, label: "child_process exec" },
        { regex: /\bexec\s*\(\s*[`'"]/, label: "exec with string" },
        { regex: /\bexecSync\s*\(/, label: "execSync" },
        { regex: /\bspawn\s*\(/, label: "spawn" },
        { regex: /\bspawnSync\s*\(/, label: "spawnSync" },
        { regex: /\beval\s*\(/, label: "eval" },
        { regex: /new\s+Function\s*\(/, label: "new Function()" },
        { regex: /require\s*\(\s*['"]child_process['"]/, label: "child_process import" },
        { regex: /from\s+['"]child_process['"]/, label: "child_process import" },
        { regex: /vm\.runIn(New|This)Context\s*\(/, label: "vm context execution" },
      ],
      content,
    );
  },
};

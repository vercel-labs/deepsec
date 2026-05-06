import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const luaNgxExecMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "lua-ngx-exec",
  description: "Lua ngx.exec/ngx.redirect/os.execute/io.popen with dynamic content",
  filePatterns: ["**/*.lua"],
  examples: [
    `ngx.exec("/internal/" .. user_path)`,
    `ngx.redirect("https://example.com/" .. target)`,
    `os.execute("rm -rf " .. dir)`,
    `local fh = io.popen(cmd)`,
    `local res = ngx.location.capture("/proxy")`,
    `ngx.exec("@upstream")`,
  ],
  match(content, filePath) {
    if (/_test\.lua$|_spec\.lua$/.test(filePath)) return [];

    return regexMatcher(
      "lua-ngx-exec",
      [
        { regex: /ngx\.exec\s*\(/, label: "ngx.exec (internal redirect)" },
        { regex: /ngx\.redirect\s*\(/, label: "ngx.redirect (external redirect)" },
        { regex: /os\.execute\s*\(/, label: "os.execute (shell command)" },
        { regex: /io\.popen\s*\(/, label: "io.popen (shell command)" },
        { regex: /ngx\.location\.capture\s*\(/, label: "ngx.location.capture (subrequest)" },
      ],
      content,
    );
  },
};

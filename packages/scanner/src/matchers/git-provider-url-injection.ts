import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const gitProviderUrlInjectionMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "git-provider-url-injection",
  description:
    "Git provider API URLs constructed with interpolated user input — path injection risk",
  filePatterns: ["**/*.{ts,tsx,js,jsx}"],
  examples: [
    `const url = \`https://api.github.com/repos/\${owner}/\${repo}\`;`,
    `await fetch(\`https://api.github.com/orgs/\${org}/members\`);`,
    `const link = \`https://github.com/\${user}/\${repo}/commits\`;`,
    `const url = \`https://gitlab.com/api/v4/projects/\${id}\`;`,
    `const url = \`https://bitbucket.org/api/2.0/repositories/\${slug}\`;`,
    `const u = \`https://git.example.com/repos/\${slug}\`;`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    return regexMatcher(
      "git-provider-url-injection",
      [
        { regex: /api\.github\.com[^`'"]{0,200}\$\{/, label: "GitHub API URL with interpolation" },
        { regex: /github\.com\/[^`'"]{0,200}\$\{/, label: "GitHub URL with interpolated path" },
        { regex: /gitlab\.com[^`'"]{0,200}\$\{/, label: "GitLab URL with interpolation" },
        { regex: /bitbucket\.org[^`'"]{0,200}\$\{/, label: "Bitbucket URL with interpolation" },
        {
          regex: /`https?:\/\/[^`]{0,80}git[^`]{0,80}\$\{/,
          label: "Git provider URL with interpolation",
        },
      ],
      content,
    );
  },
};

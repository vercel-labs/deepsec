import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const xssMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "xss",
  description: "Unsafe innerHTML, dangerouslySetInnerHTML, template injection patterns",
  filePatterns: ["**/*.{ts,tsx,js,jsx,html,ejs,hbs}"],
  examples: [
    `<div dangerouslySetInnerHTML={{ __html: x }} />`,
    `el.innerHTML = userInput;`,
    `node.outerHTML = data;`,
    `document.write(payload);`,
    `const html = \`<p>\${value}</p>\`;`,
    `<div v-html="raw" />`,
    `<span [innerHTML]="bound"></span>`,
  ],
  match(content, _filePath) {
    return regexMatcher(
      "xss",
      [
        { regex: /dangerouslySetInnerHTML/, label: "dangerouslySetInnerHTML" },
        { regex: /\.innerHTML\s*=/, label: "innerHTML assignment" },
        { regex: /\.outerHTML\s*=/, label: "outerHTML assignment" },
        { regex: /document\.write\s*\(/, label: "document.write" },
        // Bounded `.{0,120}` between `}` and the tag avoids the O(n²)
        // backtrack the unbounded version exhibited on long minified
        // lines — see commit log for the regression that motivated this.
        {
          regex: /\$\{[^}]{0,200}\}.{0,120}<\/?\w+>|<\w+[^>]{0,200}\$\{/,
          label: "template literal in HTML",
        },
        { regex: /v-html\s*=/, label: "Vue v-html directive" },
        { regex: /\[innerHTML\]\s*=/, label: "Angular innerHTML binding" },
      ],
      content,
    );
  },
};

import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

function contextSnippet(lines: string[], lineIndex: number): string {
  const start = Math.max(0, lineIndex - 2);
  const end = Math.min(lines.length, lineIndex + 3);
  return lines.slice(start, end).join("\n");
}

function hasHtmlTagAfter(line: string, start: number): boolean {
  for (let i = start; i < line.length - 1; i++) {
    if (line.charCodeAt(i) !== 60 /* < */) continue;
    const next = line.charCodeAt(i + 1);
    const afterSlash = next === 47 /* / */ ? line.charCodeAt(i + 2) : next;
    if ((afterSlash >= 65 && afterSlash <= 90) || (afterSlash >= 97 && afterSlash <= 122)) return true;
  }
  return false;
}

function hasInterpolationInsideHtmlTag(line: string): boolean {
  let searchFrom = 0;
  while (searchFrom < line.length) {
    const tagStart = line.indexOf("<", searchFrom);
    if (tagStart === -1) return false;

    const next = line.charCodeAt(tagStart + 1);
    const afterSlash = next === 47 /* / */ ? line.charCodeAt(tagStart + 2) : next;
    if (!((afterSlash >= 65 && afterSlash <= 90) || (afterSlash >= 97 && afterSlash <= 122))) {
      searchFrom = tagStart + 1;
      continue;
    }

    const interpolation = line.indexOf("${", tagStart + 1);
    if (interpolation === -1) return false;

    const tagEnd = line.indexOf(">", tagStart + 1);
    if (tagEnd === -1) return true;
    if (interpolation < tagEnd) return true;

    searchFrom = tagEnd + 1;
  }
  return false;
}

function findTemplateLiteralHtml(content: string): CandidateMatch[] {
  const lines = content.split("\n");
  const hitLines: number[] = [];
  let snippet = "";

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const interpolation = line.indexOf("${");
    if (interpolation === -1) continue;

    if (hasHtmlTagAfter(line, interpolation + 2) || hasInterpolationInsideHtmlTag(line)) {
      hitLines.push(i + 1);
      if (!snippet) snippet = contextSnippet(lines, i);
    }
  }

  return hitLines.length > 0
    ? [
        {
          vulnSlug: "xss",
          lineNumbers: hitLines,
          snippet,
          matchedPattern: "template literal in HTML",
        },
      ]
    : [];
}

export const xssMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "xss",
  description: "Unsafe innerHTML, dangerouslySetInnerHTML, template injection patterns",
  filePatterns: ["**/*.{ts,tsx,js,jsx,html,ejs,hbs}"],
  match(content, _filePath) {
    return [
      ...regexMatcher(
        "xss",
        [
          { regex: /dangerouslySetInnerHTML/, label: "dangerouslySetInnerHTML" },
          { regex: /\.innerHTML\s*=/, label: "innerHTML assignment" },
          { regex: /\.outerHTML\s*=/, label: "outerHTML assignment" },
          { regex: /document\.write\s*\(/, label: "document.write" },
          { regex: /v-html\s*=/, label: "Vue v-html directive" },
          { regex: /\[innerHTML\]\s*=/, label: "Angular innerHTML binding" },
        ],
        content,
      ),
      ...findTemplateLiteralHtml(content),
    ];
  },
};

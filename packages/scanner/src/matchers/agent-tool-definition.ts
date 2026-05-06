import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * AI agent tool definitions — functions that agents can invoke to execute code,
 * run CLI commands, access APIs, or modify state. These are prompt injection
 * attack surfaces: if an attacker controls agent input, tools are the payload.
 */
export const agentToolDefinitionMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "agent-tool-definition",
  description:
    "AI agent tool definitions — prompt injection attack surface (code execution, API access)",
  filePatterns: [
    "**/tools/**/*.{ts,tsx,js,jsx}",
    "**/agent/**/*.{ts,tsx,js,jsx}",
    "**/agents/**/*.{ts,tsx,js,jsx}",
    "**/*tool*.{ts,tsx,js,jsx}",
    "**/*agent*.{ts,tsx,js,jsx}",
  ],
  examples: [
    `const myTool = tool({\n  description: "do thing",\n  parameters: z.object({}),\n  execute: async () => ({}),\n});`,
    `const t = createTool({ name: "x", execute: async () => ({}) });`,
    `const t = defineTool({ name: "x" });`,
    `import { exec } from "child_process";\nexec(userInput);`,
    `eval(userInput);`,
    `import fs from "fs";\nfs.writeFile(path, data, () => {});`,
    `await fetch(url);`,
    `import { sandbox } from "sandbox";\nawait sandbox.runCode(code);`,
    `import { DynamicTool } from "langchain/tools";\nconst t = new DynamicTool({ name: "x" });`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    const patterns: { regex: RegExp; label: string }[] = [
      // AI SDK tool definitions
      { regex: /tool\s*\(\s*\{/, label: "AI SDK tool definition — agent-callable function" },
      { regex: /createTool|defineTool/, label: "Tool factory — agent-callable function" },
      // Dangerous tool operations
      {
        regex: /exec\(|execSync\(|spawn\(|child_process/,
        label: "Tool executes shell commands — RCE via prompt injection",
      },
      {
        regex: /eval\(|new Function\(|vm\.run/,
        label: "Tool evaluates code — RCE via prompt injection",
      },
      { regex: /writeFile|fs\.write|fs\.mkdir/, label: "Tool writes to filesystem" },
      {
        regex: /fetch\(|axios|http\.request/,
        label: "Tool makes HTTP requests — SSRF via prompt injection",
      },
      // Sandbox execution
      { regex: /sandbox|Sandbox|runCode|executeCode/, label: "Sandbox code execution tool" },
      // LangChain/similar
      { regex: /DynamicTool|StructuredTool|BaseTool/, label: "LangChain tool definition" },
    ];

    for (const { regex, label } of patterns) {
      for (let i = 0; i < lines.length; i++) {
        if (regex.test(lines[i])) {
          const start = Math.max(0, i - 1);
          const end = Math.min(lines.length, i + 4);
          matches.push({
            vulnSlug: "agent-tool-definition",
            lineNumbers: [i + 1],
            snippet: lines.slice(start, end).join("\n"),
            matchedPattern: label,
          });
        }
      }
    }

    return matches;
  },
};

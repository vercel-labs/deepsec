import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Model Context Protocol (MCP) server-side tool handlers. Every MCP tool
 * runs under the connecting client's auth scope. The risks:
 *   - Tool input schema not validating shell-metacharacters / path traversal
 *   - Tool description that an LLM can be tricked into using "out of scope"
 *   - Mutation tools without explicit per-action authorization
 *   - Tool output that includes other users' data leaking via the LLM
 *
 * Flags every file that registers an MCP tool so a downstream investigation
 * can verify auth + input validation per tool.
 */
export const mcpToolHandlerMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "mcp-tool-handler",
  description: "MCP server tool handlers — verify per-tool authz + input validation",
  filePatterns: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.mjs"],
  requires: { tech: ["mcp"] },
  examples: [
    `import { McpServer } from "@modelcontextprotocol/sdk/server/index.js";\nserver.tool("read_file", schema, async (args) => ({}));`,
    `import { McpServer } from "@modelcontextprotocol/sdk/server/index.js";\nregisterTool(server, { name: "exec" });`,
    `import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";\nserver.setRequestHandler(CallToolRequestSchema, async (req) => ({}));`,
    `import { ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";\nserver.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [] }));`,
    `import { McpServer } from "@modelcontextprotocol/sdk/server/index.js";\nconst server = new McpServer({ name: "x", version: "1" });`,
    `import { McpAgent } from "@modelcontextprotocol/sdk/server/index.js";\nconst agent = new McpAgent({ name: "x" });`,
    `import { McpServer } from "@modelcontextprotocol/sdk/server/index.js";\nserver.resource("memo", uri, async () => ({}));`,
    `import { McpServer } from "@modelcontextprotocol/sdk/server/index.js";\nserver.prompt("greet", schema, async (args) => ({}));`,
    `import { McpServer } from "@modelcontextprotocol/sdk/server/index.js";\nregisterResource(server, { uri: "x" });`,
    `import { McpServer } from "@modelcontextprotocol/sdk/server/index.js";\nregisterPrompt(server, { name: "x" });`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)$/.test(filePath)) return [];
    if (/\.d\.ts$/.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    const HAS_MCP = /\bfrom\s+["']@modelcontextprotocol\/sdk[^"']*["']|\bMcpServer\b|\bMcpAgent\b/;
    if (!HAS_MCP.test(content)) return [];

    const lines = content.split("\n");
    const matches: CandidateMatch[] = [];

    const PATTERNS: { regex: RegExp; label: string }[] = [
      { regex: /\bserver\.\s*tool\s*\(/, label: "MCP tool registration: server.tool(...)" },
      { regex: /\bregisterTool\s*\(/, label: "MCP registerTool(...)" },
      {
        regex: /setRequestHandler\s*\(\s*CallToolRequestSchema/,
        label: "MCP CallTool handler",
      },
      {
        regex: /setRequestHandler\s*\(\s*ListToolsRequestSchema/,
        label: "MCP ListTools handler — verify scope to authenticated client",
      },
      { regex: /\bnew McpServer\s*\(/, label: "MCP server construction site" },
      { regex: /\bnew McpAgent\s*\(/, label: "MCP agent construction site" },
      {
        regex: /\bregisterResource\s*\(|\bserver\.\s*resource\s*\(/,
        label: "MCP resource registration",
      },
      {
        regex: /\bregisterPrompt\s*\(|\bserver\.\s*prompt\s*\(/,
        label: "MCP prompt registration",
      },
    ];

    const hits = new Set<number>();
    for (let i = 0; i < lines.length; i++) {
      for (const { regex, label } of PATTERNS) {
        if (regex.test(lines[i])) {
          if (hits.has(i)) continue;
          hits.add(i);
          const start = Math.max(0, i - 1);
          const end = Math.min(lines.length, i + 5);
          matches.push({
            vulnSlug: "mcp-tool-handler",
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

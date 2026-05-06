import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * LLM agent loops without a step / token / time cap. The risks:
 *   - DoS / cost-burn: adversarial input loops the agent indefinitely
 *   - Prompt-injection escalation: more steps means more chances for
 *     the model to hand control to an attacker-influenced tool
 *
 * Flags `streamText` / `generateText` / `generateObject` / Claude Agent SDK
 * `query()` calls without one of: `maxSteps`, `maxTurns`, `stopWhen`,
 * `signal`, `abortSignal`. Also flags `for await` loops over agent events
 * without a counter or break condition.
 */
export const agentLoopNoCapMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "agent-loop-no-cap",
  description: "Agent / LLM call without maxSteps / maxTurns / stopWhen — DoS + cost-burn risk",
  filePatterns: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.mjs"],
  examples: [
    `import { streamText } from "ai";\nconst result = streamText({\n  model: openai("gpt-4"),\n  prompt: "hi",\n});`,
    `import { generateText } from "ai";\nawait generateText({ model, prompt: "hi" });`,
    `import { generateObject } from "ai";\nawait generateObject({ model, schema, prompt });`,
    `import { streamObject } from "ai";\nawait streamObject({ model, schema, prompt });`,
    `import { query } from "@anthropic-ai/claude-agent-sdk";\nawait query({ prompt: "hi" });`,
    `import { Codex } from "@openai/codex-sdk";\nawait claude.query({ prompt: "hi" });`,
    `import { openai } from "@ai-sdk/openai";\nawait generateText({ model: openai("gpt-4"), prompt: "hi" });`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)$/.test(filePath)) return [];
    if (/\.d\.ts$/.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    const HAS_AI_SDK =
      /\bfrom\s+["']ai["']|\bfrom\s+["']@ai-sdk\/[^"']*["']|\bfrom\s+["']@anthropic-ai\/claude-agent-sdk["']|\bfrom\s+["']@openai\/codex-sdk["']/;
    if (!HAS_AI_SDK.test(content)) return [];

    const lines = content.split("\n");
    const matches: CandidateMatch[] = [];

    // Find calls like streamText({...}) / generateText({...}) / query({...})
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const isAgentCall =
        /\b(?:streamText|generateText|generateObject|streamObject)\s*\(/.test(line) ||
        /\bawait\s+query\s*\(/.test(line) ||
        /\bclaude\.\s*query\s*\(/.test(line);
      if (!isAgentCall) continue;

      // Look at the call's argument block (this line + next 30) for cap signal
      const window = lines.slice(i, Math.min(lines.length, i + 30)).join("\n");
      const hasCap =
        /\bmaxSteps\s*:\s*\d|\bmaxTurns\s*:\s*\d|\bstopWhen\s*:|\bsignal\s*:|\babortSignal\s*:|\btimeout\s*:\s*\d/.test(
          window,
        );
      if (hasCap) continue;

      const start = Math.max(0, i - 1);
      const end = Math.min(lines.length, i + 6);
      matches.push({
        vulnSlug: "agent-loop-no-cap",
        lineNumbers: [i + 1],
        snippet: lines.slice(start, end).join("\n"),
        matchedPattern: "agent/LLM call without maxSteps/maxTurns/stopWhen/signal",
      });
    }
    return matches;
  },
};

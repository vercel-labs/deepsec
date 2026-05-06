import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Indirect-prompt-injection sink detector. Flags prompts/messages that
 * interpolate variables coming from external/untrusted sources (CRM notes,
 * scraped HTML, Snowflake/BigQuery rows, document attachments, KB docs,
 * Slack history). These need explicit untrusted-content boundaries, length
 * caps, and a system prompt that tells the model to treat the content as
 * data rather than instructions.
 *
 * Looks for two-step pattern in the same file:
 *   1. The file uses an LLM call (`streamText`, `generateText`, `messages: [`,
 *      `system: "..."`, Anthropic/OpenAI invocations).
 *   2. A prompt or message string interpolates a variable whose name signals
 *      external origin (notes, body, transcript, scraped, fetched, kb_*,
 *      salesforce*, snowflake*, etc.).
 */
export const agenticUntrustedPromptInputMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "agentic-untrusted-prompt-input",
  description: "Prompts built from external/untrusted variables — indirect prompt-injection sink",
  filePatterns: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.mjs"],
  examples: [
    `await streamText({\n  model,\n  prompt: \`Summarize: \${notes}\`,\n});`,
    `await generateText({\n  system: \`You are an assistant.\`,\n  prompt: \`Read this email: \${emailBody}\`,\n});`,
    `await generateObject({\n  messages: [\n    { role: "user", content: \`\${transcript}\` },\n  ],\n  schema,\n});`,
    `await openai.chat.completions.create({\n  messages: [{ role: "system", content: \`Context: \${scraped}\` }],\n});`,
    `await anthropic.messages.create({\n  system: \`Use this KB:\n\${kbDocs}\`,\n  messages: [],\n});`,
    `import { streamText } from "@ai-sdk/openai";\nawait streamText({\n  prompt: \`Notes from CRM: \${leadNotes}\`,\n  model,\n});`,
    `await generateText({\n  input: \`Web research: \${webpage}\`,\n  model,\n});`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)$/.test(filePath)) return [];
    if (/\.d\.ts$/.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    // Phase 1: file must look like an LLM call site
    const LLM_HINT =
      /\b(?:streamText|generateText|generateObject|streamObject|messages\s*:\s*\[|anthropic\.|openai\.|gateway\(|getGatewayModelString|claude_agent|ClaudeAgent|claude-agent|@ai-sdk\/|ai\/sdk)\b/;
    if (!LLM_HINT.test(content)) return [];

    const UNTRUSTED_VAR =
      /\b(?:notes|description|body|content|text|summary|email|emailBody|transcript|scraped|fetched|webpage|web_research|attachment|document|kb_?[A-Z]?[a-z]+|salesforce[A-Z][a-z]+|sfdc[A-Z][a-z]+|snowflake[A-Z][a-z]+|bigquery[A-Z][a-z]+|leadNotes|accountNotes|opportunityNotes|messageHistory|slackHistory|exaResult|perplexity[A-Z]?|crawlResult|browserbaseResult|crawled|recon[A-Z][a-z]+)\b/;

    // Look for prompt/message strings whose interpolation includes an
    // untrusted variable. Heuristic: a backtick template string within a
    // few lines of `system:` / `prompt:` / `content:` / `messages:`.
    const lines = content.split("\n");
    const matches: CandidateMatch[] = [];
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const isPromptKey =
        /\b(?:system|user|prompt|content|messages|input|instructions)\s*:\s*[`'"]/.test(line) ||
        /\b(?:system|user|prompt|content|messages|input|instructions)\s*:\s*\[/.test(line);
      if (!isPromptKey) continue;

      // Scan a 30-line window for `${untrustedVar}` interpolation
      const end = Math.min(lines.length, i + 30);
      for (let j = i; j < end; j++) {
        const m = lines[j].match(/\$\{([^}]+)\}/);
        if (!m) continue;
        if (UNTRUSTED_VAR.test(m[1])) {
          const start = Math.max(0, i - 2);
          matches.push({
            vulnSlug: "agentic-untrusted-prompt-input",
            lineNumbers: [j + 1],
            snippet: lines.slice(start, Math.min(lines.length, j + 3)).join("\n"),
            matchedPattern: `prompt interpolates untrusted: ${m[1].slice(0, 80)}`,
          });
          break;
        }
      }
    }
    return matches;
  },
};

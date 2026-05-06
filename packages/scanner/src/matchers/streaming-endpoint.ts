import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * AI/LLM streaming endpoints — these often bypass standard auth patterns,
 * may leak internal state via streaming, and are targets for prompt injection
 * and resource exhaustion.
 */
export const streamingEndpointMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "streaming-endpoint",
  description: "AI streaming endpoints — auth bypass, prompt injection, state leakage risk",
  filePatterns: [
    "**/route.{ts,tsx,js,jsx}",
    "**/api/**/*.{ts,tsx,js,jsx}",
    "**/app/**/*.{ts,tsx,js,jsx}",
  ],
  examples: [
    `const result = streamText({ model, messages });`,
    `const stream = streamObject({ model, schema, prompt });`,
    `const out = await generateText({ model, prompt });`,
    `return new StreamingTextResponse(stream);`,
    `const stream = new ReadableStream({ start(c) { c.enqueue("hi"); } });`,
    `const tx = new TransformStream();`,
    `const res = await openai.chat.completions.create({ model: "gpt-4", stream: true });`,
    `const r = await client.chat.completions.create({ model, messages, stream: true });`,
    `fetch("/api/chat", { method: "POST" });`,
    `app.post("/api/completion", handler);`,
    `await fetch("/api/generate", { method: "POST" });`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    const patterns: { regex: RegExp; label: string }[] = [
      // AI SDK streaming
      { regex: /streamText\s*\(/, label: "AI SDK streamText — streaming LLM endpoint" },
      { regex: /streamObject\s*\(/, label: "AI SDK streamObject — streaming structured output" },
      { regex: /generateText\s*\(/, label: "AI SDK generateText — LLM generation endpoint" },
      { regex: /StreamingTextResponse/, label: "StreamingTextResponse — legacy streaming pattern" },
      // Raw streaming responses
      { regex: /new\s+ReadableStream/, label: "ReadableStream — raw streaming response" },
      { regex: /TransformStream/, label: "TransformStream — streaming pipeline" },
      // OpenAI/Anthropic direct
      {
        regex: /openai.{0,80}stream.{0,40}true|stream:\s*true/i,
        label: "LLM API call with streaming enabled",
      },
      {
        regex: /\.chat\.completions\.create[^)]{0,200}stream/i,
        label: "OpenAI chat completion stream",
      },
      // Chat/completion endpoints
      {
        regex: /\/api\/chat|\/api\/completion|\/api\/generate/i,
        label: "AI chat/completion API route",
      },
    ];

    for (const { regex, label } of patterns) {
      for (let i = 0; i < lines.length; i++) {
        if (regex.test(lines[i])) {
          const start = Math.max(0, i - 2);
          const end = Math.min(lines.length, i + 3);
          matches.push({
            vulnSlug: "streaming-endpoint",
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

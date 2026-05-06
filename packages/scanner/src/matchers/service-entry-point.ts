import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * API repo: Finds all service entry points — Lambda handlers, event consumers,
 * cron jobs, and endpoint files. These are the attack surface of the API.
 */
export const serviceEntryPointMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "service-entry-point",
  description:
    "Lambda handlers, event consumers, cron jobs, and API endpoints in services (weak candidate)",
  filePatterns: [
    "**/services/**/src/index.ts",
    "**/services/**/src/event-consumer.ts",
    "**/services/**/src/endpoint.ts",
    "**/services/**/src/endpoints/**/*.ts",
    "**/services/**/src/handler.ts",
    "**/services/**/src/handlers/**/*.ts",
  ],
  examples: [
    `export default (event) => process(event);`,
    `export default async (event) => handle(event);`,
    `export default async function handler(event) { return ok(); }`,
    `const c = new EventConsumer();`,
    `import { eventConsumer } from "./bus";`,
    `const ep = createEndpoint(spec);`,
    `registerEndpoint(api, def);`,
    `const router = createRouter();`,
    `await handleRequest(req);`,
    `const r = routeHandler(req);`,
    `export const POST = withSchema(schema, handler);`,
  ],
  match(content, filePath) {
    // Skip test files
    if (/\.(test|spec)\./i.test(filePath)) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    const entryPatterns: { regex: RegExp; label: string }[] = [
      // Lambda-style handlers
      {
        regex: /export\s+default\s+(async\s+)?(function\s*)?\(/,
        label: "Lambda default export handler (weak candidate)",
      },
      {
        regex: /export\s+default\s+async\s+function\b/,
        label: "Lambda default export handler (weak candidate)",
      },
      // Event consumers
      {
        regex: /eventConsumer|event-consumer|EventConsumer/,
        label: "Event consumer entry point (weak candidate)",
      },
      // Endpoint definitions
      {
        regex: /createEndpoint|registerEndpoint/,
        label: "Service endpoint registration (weak candidate)",
      },
      // Express-style route registration
      {
        regex: /handleRequest|routeHandler|createRouter/,
        label: "Request handler (weak candidate)",
      },
      // withSchema in apps
      {
        regex: /withSchema\s*\(/,
        label: "withSchema route handler (weak candidate)",
      },
    ];

    for (const { regex, label } of entryPatterns) {
      for (let i = 0; i < lines.length; i++) {
        if (regex.test(lines[i])) {
          const start = Math.max(0, i - 2);
          const end = Math.min(lines.length, i + 3);
          matches.push({
            vulnSlug: "service-entry-point",
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

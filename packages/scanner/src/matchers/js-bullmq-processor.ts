import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const jsBullmqProcessorMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "js-bullmq-processor",
  description:
    "BullMQ workers and queue processors — background-job auth-gap surface (gated on bullmq)",
  filePatterns: ["**/*.{ts,js,mjs,cjs}"],
  requires: { tech: ["bullmq"] },
  examples: [
    `const worker = new Worker('emails', async (job) => {});`,
    `new Worker("payments", processPayment, { connection })`,
    `const queue = new Queue('emails', { connection })`,
    `new Queue("notifications")`,
    `queue.process(async (job) => { return doWork(job) })`,
    `const { userId, payload } = job.data;`,
    `console.log(job.data.email)`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    return regexMatcher(
      "js-bullmq-processor",
      [
        { regex: /new\s+Worker\s*\(\s*['"][^'"]+['"]\s*,/, label: "new Worker('queue', handler)" },
        { regex: /new\s+Queue\s*\(\s*['"][^'"]+['"]/, label: "new Queue() declaration" },
        {
          regex: /\.process\s*\(\s*async\s*\(\s*job\b/,
          label: "queue.process(async job => ...) handler body",
        },
        { regex: /\bjob\.data\b/, label: "job.data — payload trust boundary" },
      ],
      content,
    );
  },
};

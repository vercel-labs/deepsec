import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const azureFunctionHandlerMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "azure-function-handler",
  description: "Azure Functions Node/Python/JS handler signatures (gated on Azure Functions)",
  filePatterns: ["**/*.{ts,js,mjs,cjs,py}", "**/function.json"],
  requires: { tech: ["azure-functions"] },
  examples: [
    `module.exports = async function (context, req) { context.res = { body: "ok" } }`,
    `module.exports = async function(context, req) {\n  context.log("hi");\n}`,
    `def main(req: func.HttpRequest) -> func.HttpResponse:\n    return func.HttpResponse("hi")`,
    `{ "authLevel": "anonymous", "type": "httpTrigger" }`,
    `{ "authLevel": "function" }`,
    `{ "authLevel": "admin" }`,
    `app.http('httpTrigger1', { methods: ['GET'], handler: async (req, ctx) => {} })`,
    `app.http("api", { handler: myHandler })`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    return regexMatcher(
      "azure-function-handler",
      [
        {
          regex: /module\.exports\s*=\s*async\s*function\s*\(\s*context\b/,
          label: "module.exports = async function(context, req) — Azure Functions Node",
        },
        {
          regex: /^\s*def\s+main\s*\(\s*req\s*:\s*func\.HttpRequest/m,
          label: "Python def main(req: func.HttpRequest)",
        },
        {
          regex: /"authLevel"\s*:\s*"(?:anonymous|function|admin)"/,
          label: "function.json authLevel — confirm anonymous is intentional",
        },
        {
          regex: /\bapp\.http\s*\(\s*['"][^'"]+['"]\s*,/,
          label: "app.http('name', { handler }) — Functions v4 model",
        },
      ],
      content,
    );
  },
};

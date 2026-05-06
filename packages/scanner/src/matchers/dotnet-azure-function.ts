import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const dotnetAzureFunctionMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "dotnet-azure-function",
  description: "Azure Functions C# entry points (gated on Azure Functions)",
  filePatterns: ["**/*.cs"],
  requires: { tech: ["azure-functions", "dotnet"] },
  examples: [
    `[FunctionName("HttpTriggerCSharp")]`,
    `[ FunctionName ( "ProcessOrder" ) ]`,
    `[Function("MyIsolatedFunction")]`,
    `[Function ( "QueueProcessor" )]`,
    `[HttpTrigger(AuthorizationLevel.Anonymous, "get", "post")]`,
    `[HttpTrigger(AuthorizationLevel.Function, "post", Route = "items")]`,
    `[HttpTrigger(AuthorizationLevel.Admin, "delete")]`,
    `[ServiceBusTrigger("orders", Connection = "ServiceBus")]`,
    `[QueueTrigger("myqueue", Connection = "AzureWebJobsStorage")]`,
  ],
  match(content, filePath) {
    if (/\/(Tests|UnitTests|IntegrationTests)\//.test(filePath)) return [];

    return regexMatcher(
      "dotnet-azure-function",
      [
        {
          regex: /\[\s*FunctionName\s*\(\s*"[^"]+"\s*\)\s*\]/,
          label: "[FunctionName(...)] attribute",
        },
        { regex: /\[\s*Function\s*\(\s*"[^"]+"\s*\)\s*\]/, label: "[Function(...)] attribute" },
        {
          regex: /\[\s*HttpTrigger\s*\(\s*AuthorizationLevel\.(Anonymous|Function|Admin)\b/,
          label: "[HttpTrigger(AuthorizationLevel.X)] — verify Anonymous is intentional",
        },
        { regex: /\[\s*ServiceBusTrigger\b|\[\s*QueueTrigger\b/, label: "queue trigger entry" },
      ],
      content,
    );
  },
};

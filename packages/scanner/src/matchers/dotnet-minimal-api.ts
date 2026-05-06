import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const dotnetMinimalApiMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "dotnet-minimal-api",
  description: "ASP.NET Core minimal-API endpoint mappings (gated on .NET)",
  filePatterns: ["**/*.cs"],
  requires: { tech: ["dotnet"] },
  examples: [
    `app.MapGet("/users", () => users);`,
    `app.MapPost("/login", (LoginDto body) => Login(body));`,
    `app.MapPut("/items/{id}", UpdateItem);`,
    `app.MapPatch("/items/{id}", PatchItem);`,
    `app.MapDelete("/items/{id}", DeleteItem);`,
    `app.MapMethods("/api", new[] { "GET", "POST" }, Handler);`,
    `app.MapGet("/admin", AdminHandler).RequireAuthorization();`,
    `app.MapGet("/public", PublicHandler).AllowAnonymous();`,
    `var builder = WebApplication.CreateBuilder(args);`,
  ],
  match(content, filePath) {
    if (/\/(Tests|UnitTests|IntegrationTests)\//.test(filePath)) return [];

    return regexMatcher(
      "dotnet-minimal-api",
      [
        {
          regex: /\bapp\.Map(?:Get|Post|Put|Patch|Delete|Methods)\s*\(/,
          label: "app.Map<Verb> registration",
        },
        { regex: /\.RequireAuthorization\s*\(/, label: ".RequireAuthorization() — auth gate" },
        { regex: /\.AllowAnonymous\s*\(\s*\)/, label: ".AllowAnonymous() — public route" },
        {
          regex: /\bWebApplication\.CreateBuilder\s*\(/,
          label: "WebApplication.CreateBuilder() init",
        },
      ],
      content,
    );
  },
};

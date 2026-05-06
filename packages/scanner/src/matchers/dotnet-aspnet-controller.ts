import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const dotnetAspnetControllerMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "dotnet-aspnet-controller",
  description: "ASP.NET Core controllers and authorization attributes (gated on .NET)",
  filePatterns: ["**/*.cs"],
  requires: { tech: ["dotnet"] },
  examples: [
    `public class UsersController : ControllerBase`,
    `public class HomeController : Controller`,
    `[ApiController]`,
    `[ ApiController ]`,
    `[Route("api/[controller]")]`,
    `[HttpGet("{id}")]`,
    `[HttpPost]`,
    `[HttpPut("{id}")]`,
    `[HttpPatch("{id}")]`,
    `[HttpDelete("{id}")]`,
    `[HttpHead]`,
    `[HttpOptions]`,
    `[AllowAnonymous]`,
    `[Authorize]`,
    `[Authorize(Roles = "Admin")]`,
  ],
  match(content, filePath) {
    if (/\/(Tests|UnitTests|IntegrationTests)\//.test(filePath)) return [];

    return regexMatcher(
      "dotnet-aspnet-controller",
      [
        {
          regex: /\bclass\s+\w+\s*:\s*(?:Controller|ControllerBase)\b/,
          label: "ControllerBase / Controller subclass",
        },
        { regex: /\[\s*ApiController\s*\]/, label: "[ApiController] attribute" },
        { regex: /\[\s*Route\s*\(/, label: "[Route] attribute" },
        {
          regex: /\[\s*Http(?:Get|Post|Put|Patch|Delete|Head|Options)\s*\(?/,
          label: "[HttpMethod] attribute",
        },
        { regex: /\[\s*AllowAnonymous\s*\]/, label: "[AllowAnonymous] — opens public access" },
        { regex: /\[\s*Authorize(?:\s*\([^)]*\))?\s*\]/, label: "[Authorize] auth gate" },
      ],
      content,
    );
  },
};

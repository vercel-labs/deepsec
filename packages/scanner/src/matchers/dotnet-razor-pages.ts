import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const dotnetRazorPagesMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "dotnet-razor-pages",
  description: "Razor Pages OnGet/OnPost handlers (gated on .NET)",
  filePatterns: ["**/Pages/**/*.cshtml.cs", "**/*.cshtml.cs"],
  requires: { tech: ["dotnet"] },
  examples: [
    `public class IndexModel : PageModel`,
    `public class LoginModel : PageModel {`,
    `public Task OnGet() {`,
    `public Task<IActionResult> OnPost() {`,
    `public async Task OnGetAsync() {`,
    `public async Task<IActionResult> OnPostAsync() {`,
    `public async Task OnPutAsync() {`,
    `public Task<IActionResult> OnDeleteAsync() {`,
    `[BindProperty]`,
    `[BindProperty(SupportsGet = true)]`,
    `[ValidateAntiForgeryToken]`,
  ],
  match(content, filePath) {
    if (/\/(Tests|UnitTests|IntegrationTests)\//.test(filePath)) return [];

    return regexMatcher(
      "dotnet-razor-pages",
      [
        {
          regex: /\bclass\s+\w+\s*:\s*PageModel\b/,
          label: "PageModel subclass",
        },
        {
          regex:
            /\bpublic\s+(?:async\s+)?(?:Task<?[^>]*>?\s+)?On(?:Get|Post|Put|Delete)(?:Async)?\s*\(/,
          label: "OnGet/OnPost handler",
        },
        { regex: /\[\s*BindProperty\b/, label: "[BindProperty] (request-bound input)" },
        {
          regex: /\[\s*ValidateAntiForgeryToken\s*\]/,
          label: "[ValidateAntiForgeryToken] CSRF guard",
        },
      ],
      content,
    );
  },
};

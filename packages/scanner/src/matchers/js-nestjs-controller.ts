import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const jsNestjsControllerMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "js-nestjs-controller",
  description: "NestJS controllers and route methods — entry-point surface (gated on @nestjs/*)",
  filePatterns: ["**/*.{ts,js}"],
  requires: { tech: ["nestjs"] },
  examples: [
    `@Controller("users")\nexport class UsersController {}`,
    `@Controller('/api')`,
    `@Get(":id")\nfindOne() {}`,
    `@Post('login')\nlogin() {}`,
    `@Put("/x")\nupdate() {}`,
    `@Patch(':id') patch() {}`,
    `@Delete("/y")\nremove() {}`,
    `@All("*")\ncatchAll() {}`,
    `@UseGuards(JwtGuard)`,
    `@Public()\nopen() {}`,
    `findOne(@Body() body: any) {}`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    return regexMatcher(
      "js-nestjs-controller",
      [
        { regex: /@Controller\s*\(/, label: "@Controller decorator" },
        {
          regex: /@(?:Get|Post|Put|Patch|Delete|Options|Head|All)\s*\(/,
          label: "HTTP method decorator",
        },
        { regex: /@UseGuards\s*\(/, label: "@UseGuards (auth gate)" },
        { regex: /@Public\s*\(\s*\)/, label: "@Public() decorator (skips global auth)" },
        { regex: /@Body\s*\(\s*\)/, label: "@Body() (request body sink)" },
      ],
      content,
    );
  },
};

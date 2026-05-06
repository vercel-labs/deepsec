import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const jvmMicronautControllerMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "jvm-micronaut-controller",
  description: "Micronaut controllers and route methods (gated on Micronaut)",
  filePatterns: ["**/*.{java,kt}"],
  requires: { tech: ["micronaut"] },
  examples: [
    `@Controller("/users")`,
    `@Controller ( "/api/v1" )`,
    `@Get("/{id}")`,
    `@Post("/")`,
    `@Put("/{id}")`,
    `@Patch("/{id}")`,
    `@Delete("/{id}")`,
    `@Head("/health")`,
    `@Options("/items")`,
    `@Secured("ROLE_ADMIN")`,
    `@PermitAll`,
    `public User getUser(Authentication authentication) {`,
    `fun me(Authentication auth): UserDto {`,
  ],
  match(content, filePath) {
    if (/\/(test|tests)\//.test(filePath)) return [];

    return regexMatcher(
      "jvm-micronaut-controller",
      [
        { regex: /@Controller\s*\(/, label: "@Controller(...) declaration" },
        {
          regex: /@(?:Get|Post|Put|Patch|Delete|Head|Options)\s*\(/,
          label: "Micronaut HTTP method annotation",
        },
        { regex: /@Secured\s*\(/, label: "@Secured(...) auth annotation" },
        { regex: /@PermitAll\b/, label: "@PermitAll — public access" },
        { regex: /\bAuthentication\s+\w+/, label: "Authentication arg in handler" },
      ],
      content,
    );
  },
};

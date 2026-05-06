import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const jvmSpringControllerMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "jvm-spring-controller",
  description: "Spring controllers, mappings, and security config (gated on Spring)",
  filePatterns: ["**/*.{java,kt}"],
  requires: { tech: ["spring"] },
  examples: [
    `@RestController`,
    `@Controller`,
    `@GetMapping("/users")`,
    `@PostMapping("/login")`,
    `@PutMapping`,
    `@PatchMapping("/items/{id}")`,
    `@DeleteMapping("/items/{id}")`,
    `@RequestMapping(value = "/api", method = RequestMethod.GET)`,
    `@PreAuthorize("hasRole('ADMIN')")`,
    `http.authorizeRequests().antMatchers("/public/**").permitAll();`,
    `.antMatcher("/admin/**")`,
  ],
  match(content, filePath) {
    if (/\/(test|tests)\//.test(filePath)) return [];

    return regexMatcher(
      "jvm-spring-controller",
      [
        { regex: /@(?:Rest)?Controller\b/, label: "@Controller / @RestController" },
        {
          regex: /@(?:Get|Post|Put|Patch|Delete|Request)Mapping\b/,
          label: "@<Verb>Mapping",
        },
        { regex: /@PreAuthorize\s*\(/, label: "@PreAuthorize SpEL expression" },
        { regex: /\.permitAll\s*\(\s*\)/, label: ".permitAll() — opens public access" },
        { regex: /\bantMatchers?\s*\(/, label: "antMatcher(...) auth scope" },
      ],
      content,
    );
  },
};

import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const phpSlimRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "php-slim-route",
  description: "Slim Framework route registrations (gated on Slim)",
  filePatterns: ["**/*.php"],
  requires: { tech: ["slim"] },
  examples: [
    `$app->get('/users', function ($request, $response) { return $response; });`,
    `$app->post("/login", LoginAction::class);`,
    `$app->put('/items/{id}', $handler);`,
    `$app->patch('/items/{id}', $handler);`,
    `$app->delete('/items/{id}', $handler);`,
    `$app->any('/health', $healthHandler);`,
    `$app->map(['GET', 'POST'], '/x', $h);`,
    `$app->group('/api', function ($group) { /* ... */ })->add(new AuthMiddleware());`,
    `$app->add(new SessionMiddleware($settings));`,
    `$body = $request->getParsedBody();`,
    `$id = $request->getAttribute('id');`,
    `$q = $request->getQueryParams();`,
  ],
  match(content, filePath) {
    if (/\/(tests|vendor)\//.test(filePath)) return [];

    return regexMatcher(
      "php-slim-route",
      [
        {
          regex: /\$app->(?:get|post|put|patch|delete|map|any)\s*\(/,
          label: "$app->method route registration",
        },
        { regex: /\$app->group\s*\(/, label: "$app->group(...) middleware scope" },
        { regex: /->add\s*\(\s*new\s+\w+Middleware/, label: "->add(new ...Middleware) attach" },
        {
          regex: /\$request->(?:getQueryParams|getParsedBody|getAttribute)\s*\(/,
          label: "PSR-7 request accessor",
        },
      ],
      content,
    );
  },
};

import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const dartShelfHandlerMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "dart-shelf-handler",
  description: "Dart Shelf handlers and Router routes (gated on dart)",
  filePatterns: ["**/*.dart"],
  requires: { tech: ["dart"] },
  examples: [
    `final router = Router();`,
    `var app = Router()..get('/', (req) => Response.ok('hi'));`,
    `router.get('/users', listUsers);`,
    `router.post('/users', (Request req) async => Response.ok(''));`,
    `router.put('/users/<id>', updateUser);`,
    `router.patch('/users/<id>', patchUser);`,
    `router.delete('/users/<id>', deleteUser);`,
    `router.head('/health', healthCheck);`,
    `router.options('/cors', corsHandler);`,
    `router.all('/<ignored|.*>', notFound);`,
    `Response handler(Request request) { return Response.ok(''); }`,
    `Future<Response> _users(Request req) async { return Response.ok(''); }`,
    `final pipeline = Pipeline().addMiddleware(logRequests()).addHandler(router);`,
  ],
  match(content, filePath) {
    if (/\/(test|tests)\//.test(filePath)) return [];

    return regexMatcher(
      "dart-shelf-handler",
      [
        {
          regex: /\bRouter\s*\(\s*\)/,
          label: "shelf_router Router() factory",
        },
        {
          regex: /\.(?:get|post|put|patch|delete|head|options|all)\s*\(\s*'[^']+'\s*,/,
          label: "router.<verb>('/path', handler)",
        },
        {
          regex: /\bRequest\s+\w+\s*\)/,
          label: "Handler signature taking shelf Request",
        },
        { regex: /\bPipeline\s*\(\s*\)\.addMiddleware\b/, label: "Pipeline().addMiddleware" },
      ],
      content,
    );
  },
};

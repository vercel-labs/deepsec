import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const pyStarletteRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "py-starlette-route",
  description: "Starlette Route / Mount / WebSocketRoute declarations (gated on Starlette)",
  filePatterns: ["**/*.py"],
  requires: { tech: ["starlette"] },
  examples: [
    `    Route("/users", endpoint=user_list),`,
    `    Route('/items/{id}', items, methods=["GET"]),`,
    `    Mount("/static", app=StaticFiles(directory="static")),`,
    `    Mount('/api', routes=api_routes),`,
    `    WebSocketRoute("/ws", endpoint=ws_endpoint),`,
    `app.add_middleware(AuthenticationMiddleware, backend=BasicAuthBackend())`,
    `from starlette.middleware.authentication import AuthenticationMiddleware`,
  ],
  match(content, filePath) {
    if (/\b(?:tests?|migrations)\b/i.test(filePath)) return [];

    return regexMatcher(
      "py-starlette-route",
      [
        { regex: /\bRoute\s*\(\s*['"][^'"]+['"]\s*,/, label: "Route('/path', endpoint)" },
        { regex: /\bMount\s*\(\s*['"][^'"]+['"]\s*,/, label: "Mount('/sub', app)" },
        { regex: /\bWebSocketRoute\s*\(/, label: "WebSocketRoute declaration" },
        { regex: /\bAuthenticationMiddleware\b/, label: "AuthenticationMiddleware wiring" },
      ],
      content,
    );
  },
};

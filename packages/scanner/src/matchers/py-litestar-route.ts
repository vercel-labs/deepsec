import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const pyLitestarRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "py-litestar-route",
  description: "Litestar route handlers, WebSocket handlers, and guards (gated on Litestar)",
  filePatterns: ["**/*.py"],
  requires: { tech: ["litestar"] },
  examples: [
    `@get("/users")`,
    `@post("/items")`,
    `@put("/things/{item_id:int}")`,
    `@delete("/users/{user_id:int}")`,
    `@patch(path="/x")`,
    `@head(path="/health")`,
    `@options("/preflight")`,
    `@route("/raw", http_method="GET")`,
    `@get("/admin", guards=[admin_guard])`,
    `@websocket("/ws")`,
    `@get("/me", guards=[AuthGuard()])`,
    `router = Router(path="/v1", route_handlers=[user_handler])`,
    `    route_handlers=[ItemController],`,
    `handler = HTTPRouteHandler("/users", user_handler)`,
    `ws = WebsocketRouteHandler("/ws", ws_handler)`,
  ],
  match(content, filePath) {
    if (/\b(?:tests?|migrations)\b/i.test(filePath)) return [];

    return regexMatcher(
      "py-litestar-route",
      [
        {
          // Only the bare handler decorators (`from litestar import get`) are
          // matched. The `@app.get(...)` form is intentionally omitted: a
          // generic attribute walk adds a lot of noise for little signal, and
          // Litestar projects overwhelmingly use the bare form.
          regex: /^\s*@(?:get|post|put|patch|delete|head|options|trace|websocket|route)\s*\(/m,
          label: "Litestar handler decorator",
        },
        {
          // Litestar spells the WebSocket handler class `WebsocketRouteHandler`
          // (lowercase `s`) and exports it as `litestar.handlers.WebsocketRouteHandler`.
          // `WebSocketRoute` (capital `S`) is a different class — the *route*
          // object, not the handler — so it must not match here.
          // https://docs.litestar.dev/main/_modules/litestar/handlers/websocket_handlers/route_handler.html
          regex: /\b(?:HTTPRouteHandler|WebsocketRouteHandler)\s*\(/,
          label: "HTTPRouteHandler/WebsocketRouteHandler",
        },
        { regex: /\bRouter\s*\(/, label: "Router() factory" },
        { regex: /\broute_handlers\s*=/, label: "route_handlers= registration" },
        {
          regex: /\bguards\s*=/,
          label: "guards=... guard (auth gate when wired up)",
        },
      ],
      content,
    );
  },
};

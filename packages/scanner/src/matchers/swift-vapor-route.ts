import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const swiftVaporRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "swift-vapor-route",
  description: "Swift Vapor route registrations (gated on Vapor)",
  filePatterns: ["**/*.swift"],
  requires: { tech: ["vapor"] },
  examples: [
    `app.get("hello") { req in return "hi" }`,
    `app.post("users") { req async throws -> User in }`,
    `app.put("users", ":id") { req in }`,
    `app.patch("users", ":id") { req in }`,
    `app.delete("users", ":id") { req in }`,
    `app.on(.POST, "upload", body: .stream) { req in }`,
    `let protected = app.grouped(User.guardMiddleware())`,
    `let secured = routes.grouped(Token.authenticator())`,
    `let id = req.parameters.get("id")`,
    `let q = try req.query.decode(Search.self)`,
    `let body = try req.content.decode(User.self)`,
    `let user = try req.auth.require(User.self)`,
    `let auth = req.headers.bearerAuthorization`,
    `final class UserController: RouteCollection {}`,
    `class AdminController : RouteCollection {`,
  ],
  match(content, filePath) {
    if (/\/(Tests|tests)\//.test(filePath)) return [];

    return regexMatcher(
      "swift-vapor-route",
      [
        {
          regex: /\bapp\.(?:get|post|put|patch|delete|on)\s*\(/,
          label: "app.<verb>('/path') registration",
        },
        {
          regex: /\bgrouped\s*\(\s*\w+\.[A-Za-z]+\(\)\s*\)/,
          label: ".grouped(Middleware()) auth scope",
        },
        { regex: /\breq\.(?:parameters|query|content|auth|headers)\b/, label: "req.* accessor" },
        {
          regex: /\bclass\s+\w+Controller\s*:\s*RouteCollection\b/,
          label: "RouteCollection conformance",
        },
      ],
      content,
    );
  },
};

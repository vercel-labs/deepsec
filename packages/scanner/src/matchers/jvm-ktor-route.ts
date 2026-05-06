import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const jvmKtorRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "jvm-ktor-route",
  description: "Ktor routing DSL (gated on Ktor)",
  filePatterns: ["**/*.kt"],
  requires: { tech: ["ktor"] },
  examples: [
    `routing {`,
    `routing { get("/") { call.respondText("hi") } }`,
    `get("/users") {`,
    `post("/login") {`,
    `put("/items/{id}") {`,
    `patch("/items/{id}") {`,
    `delete("/items/{id}") {`,
    `authenticate("jwt") {`,
    `authenticate("auth-session") { get("/me") { ... } }`,
    `val body = call.receive<UserDto>()`,
    `val multipart = call.receive<Multipart>()`,
  ],
  match(content, filePath) {
    if (/\/(test|tests)\//.test(filePath)) return [];

    return regexMatcher(
      "jvm-ktor-route",
      [
        {
          regex: /\brouting\s*\{/,
          label: "routing { ... } block",
        },
        {
          regex: /\b(?:get|post|put|patch|delete)\s*\(\s*"[^"]+"\s*\)\s*\{/,
          label: "<verb>('/path') { ... }",
        },
        {
          regex: /\bauthenticate\s*\(\s*"[^"]+"\s*\)\s*\{/,
          label: "authenticate('jwt') { ... } scope",
        },
        { regex: /\bcall\.receive\b/, label: "call.receive (untrusted body)" },
      ],
      content,
    );
  },
};

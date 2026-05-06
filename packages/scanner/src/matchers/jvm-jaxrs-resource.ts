import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const jvmJaxrsResourceMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "jvm-jaxrs-resource",
  description:
    "JAX-RS resources (Jersey, RESTEasy, Quarkus) — entry-point surface (gated on JAX-RS)",
  filePatterns: ["**/*.{java,kt}"],
  requires: { tech: ["jaxrs"] },
  examples: [
    `@Path("/users")`,
    `@Path ( "/api/v1/items" )`,
    `@GET`,
    `@POST`,
    `@PUT`,
    `@PATCH`,
    `@DELETE`,
    `@HEAD`,
    `@OPTIONS`,
    `@RolesAllowed("admin")`,
    `@PermitAll`,
    `public User getUser(@PathParam("id") String id) {`,
    `void search(@QueryParam("q") String q) {`,
    `void custom(@HeaderParam("X-Auth") String token) {`,
    `void submit(@FormParam("name") String name) {`,
    `void session(@CookieParam("sid") String sid) {`,
  ],
  match(content, filePath) {
    if (/\/(test|tests)\//.test(filePath)) return [];

    return regexMatcher(
      "jvm-jaxrs-resource",
      [
        { regex: /@Path\s*\(\s*"[^"]+"\s*\)/, label: "@Path declaration" },
        {
          regex: /@(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/,
          label: "JAX-RS method annotation",
        },
        { regex: /@RolesAllowed\s*\(/, label: "@RolesAllowed auth gate" },
        { regex: /@PermitAll\b/, label: "@PermitAll opens public access" },
        {
          regex: /@(?:Path|Query|Header|Form|Cookie)Param\s*\(/,
          label: "param extractor (untrusted)",
        },
      ],
      content,
    );
  },
};

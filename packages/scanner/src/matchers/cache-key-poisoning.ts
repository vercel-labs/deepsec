import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const cacheKeyPoisoningMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "cache-key-poisoning",
  description: "Cache key construction with attacker-controlled values — poisoning risk",
  filePatterns: ["**/*.{lua,go,ts,js}"],
  examples: [
    `const cacheKey = "u:" + req.headers.host;`,
    `const cache_key = host + ":" + path;`,
    `const cacheKey = req.headers["x-tenant"];`,
    `const cache_key = req.header("x-trace");`,
    `const cacheKey = url + req.query.foo;`,
    `const cache_key = JSON.stringify(query);`,
    `Vary: Accept-Language, Accept-Encoding`,
    `Vary: Cookie`,
    `ngx.shared.cache:set(ngx.var.host .. path, val)`,
    `ngx.shared.dict:set("k:" .. ngx.var.request_uri, val)`,
    `redis.set("cache:" + req.body.id, value);`,
    `redis.hset("cache:host", host, value);`,
    `store.set("cache:" + req.body.k, v);`,
    `kv.set("cache:" + host, blob);`,
  ],
  match(content, filePath) {
    if (/_test\.|_spec\.|\.test\.|\.spec\./.test(filePath)) return [];

    return regexMatcher(
      "cache-key-poisoning",
      [
        {
          regex: /cache.{0,80}key.{0,80}host|cache_key.{0,80}host/i,
          label: "Cache key includes Host header",
        },
        {
          regex: /cache.{0,80}key.{0,80}header|cache_key.{0,80}header/i,
          label: "Cache key includes request header",
        },
        {
          regex: /cache.{0,80}key.{0,80}query|cache_key.{0,80}query/i,
          label: "Cache key includes query params",
        },
        {
          regex: /vary.{0,40}:.{0,80}accept|vary.{0,40}:.{0,80}cookie/i,
          label: "Vary header includes client-controlled values",
        },
        {
          regex: /ngx\.shared\.\w+:set\s*\([^)]{0,200}ngx\.var\.host/,
          label: "Shared dict keyed by Host header",
        },
        {
          regex: /ngx\.shared\.\w+:set\s*\([^)]{0,200}ngx\.var\.request_uri/,
          label: "Shared dict keyed by request URI",
        },
        {
          regex: /redis\.\w*set\s*\([^)]{0,200}req\.|redis\.\w*set\s*\([^)]{0,200}host/i,
          label: "Redis set with request-derived key",
        },
        {
          regex:
            /\.set\s*\([^)]{0,200}cache[^)]{0,80}req\.|\.set\s*\([^)]{0,200}cache[^)]{0,80}host/i,
          label: "Cache set with request-derived data",
        },
      ],
      content,
    );
  },
};

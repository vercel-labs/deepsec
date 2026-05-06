import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const jsGraphqlResolverMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "js-graphql-resolver",
  description:
    "GraphQL resolvers (Apollo / Yoga / Mercurius) — entry-point surface (gated on graphql)",
  filePatterns: ["**/*.{ts,js,mjs,cjs}"],
  requires: { tech: ["graphql"] },
  examples: [
    `const resolvers = { Query: { user: () => null } }`,
    `const resolver = { Query: { me: () => null } }`,
    `Mutation: { createUser: async (_p, args) => ({}) }`,
    `Subscription: { onMessage: { subscribe: () => pubsub.asyncIterator("MSG") } }`,
    `@Query(() => User)\n  async user() {}`,
    `@Mutation(() => Boolean)\n  async deleteUser() {}`,
    `@Resolver(() => User)\nclass UserResolver {}`,
    `const userId = context.userId;`,
    `if (!context.user) throw new Error("unauth")`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    return regexMatcher(
      "js-graphql-resolver",
      [
        {
          regex: /\bresolvers?\s*[:=]\s*\{\s*Query\s*:/,
          label: "resolvers Query map",
        },
        { regex: /\bMutation\s*:\s*\{/, label: "Mutation resolver map" },
        { regex: /\bSubscription\s*:\s*\{/, label: "Subscription resolver" },
        {
          regex: /@(?:Query|Mutation|Resolver)\s*\(/,
          label: "type-graphql / Nest GraphQL decorator",
        },
        { regex: /\bcontext\.\w+/, label: "context.* (auth identity carrier — confirm wiring)" },
      ],
      content,
    );
  },
};

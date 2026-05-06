import type { CandidateMatch, MatcherPlugin } from "@deepsec/core";

/**
 * tRPC procedures defined as `publicProcedure` that look like they should be
 * authenticated (file lives under a "viewer"/"admin"/"settings"/"organization"
 * router, or the procedure body reads `ctx.session`/`ctx.user`/`ctx.userId`).
 *
 * Mis-pickng `publicProcedure` instead of `authedProcedure` /
 * `protectedProcedure` is a recurring auth-bypass shape: an attacker can hit
 * the endpoint without authenticating, and the handler quietly treats the
 * absent user as an "anonymous viewer" instead of rejecting the call.
 */
export const trpcPublicProcedureMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "trpc-public-procedure",
  description:
    "tRPC publicProcedure used in a router that looks authenticated — verify it should not be authedProcedure",
  filePatterns: ["**/*.ts", "**/*.tsx"],
  requires: { tech: ["trpc"] },
  examples: [
    `export const listUsers = publicProcedure.query(({ ctx }) => {\n  return ctx.prisma.user.findMany({ where: { id: ctx.session.user.id } });\n});`,
    `publicProcedure.input(z.object({})).mutation(({ ctx }) => {\n  return ctx.user.id;\n});`,
    `publicProcedure.input(schema).query(async ({ ctx, input }) => {\n  const userId = ctx.userId;\n  return userId;\n});`,
    `publicProcedure.use(async ({ ctx, next }) => {\n  if (!ctx.session) throw new Error();\n  return next();\n});`,
    `export const getMe = publicProcedure.query(({ ctx }) => {\n  return ctx.currentUser;\n});`,
    `publicProcedure.mutation(async ({ ctx }) => {\n  return getSession(ctx);\n});`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\.(ts|tsx)$/.test(filePath)) return [];
    if (/\.d\.ts$/.test(filePath)) return [];

    if (!/\bpublicProcedure\b/.test(content)) return [];
    // Skip the procedure-definition file itself and obvious public router files.
    if (/\/procedures\/publicProcedure\.|\/publicViewer\//.test(filePath)) return [];

    const lines = content.split("\n");
    const matches: CandidateMatch[] = [];

    const sessionAccess = /\bctx\.(?:session|user|userId|currentUser|prisma)|getSession\s*\(\s*ctx/;
    const fileLooksAuthed =
      /\/(?:viewer|admin|organizations?|teams?|settings|billing|payments?|workflows?)\//.test(
        filePath,
      );

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!/\bpublicProcedure\s*\.\s*(?:input|query|mutation|use)\b/.test(line)) continue;

      const start = Math.max(0, i - 2);
      const end = Math.min(lines.length, i + 12);
      const window = lines.slice(start, end).join("\n");
      const reachesSession = sessionAccess.test(window);

      if (!fileLooksAuthed && !reachesSession) continue;

      let label = "publicProcedure used in router that looks authenticated";
      if (reachesSession) label += " (handler reads ctx.session/user) — verify intent";
      else label += " — verify intent";

      matches.push({
        vulnSlug: "trpc-public-procedure",
        lineNumbers: [i + 1],
        snippet: lines.slice(start, Math.min(lines.length, i + 4)).join("\n"),
        matchedPattern: label,
      });
    }

    return matches;
  },
};

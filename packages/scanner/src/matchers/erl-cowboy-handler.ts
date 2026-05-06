import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const erlCowboyHandlerMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "erl-cowboy-handler",
  description: "Erlang Cowboy HTTP handlers (gated on Erlang)",
  filePatterns: ["**/*.erl"],
  requires: { tech: ["erlang"] },
  examples: [
    `init(Req, State) ->\n    {ok, Req, State}.`,
    `init(Req, State) -> {cowboy_rest, Req, State}.`,
    `Dispatch = cowboy_router:compile([{'_', [{"/", hello_handler, []}]}]),`,
    `cowboy_router:compile([{Host, Routes}])`,
    `Id = cowboy_req:binding(id, Req),`,
    `Qs = cowboy_req:qs(Req),`,
    `{ok, Body, Req2} = cowboy_req:read_body(Req),`,
    `Auth = cowboy_req:header(<<"authorization">>, Req),`,
  ],
  match(content, filePath) {
    if (/\/(test|tests)\//.test(filePath)) return [];

    return regexMatcher(
      "erl-cowboy-handler",
      [
        {
          regex: /\binit\s*\(\s*Req\s*,\s*State\s*\)\s*->/,
          label: "init(Req, State) — cowboy handler entry",
        },
        {
          regex: /\bcowboy_router:compile\b/,
          label: "cowboy_router:compile([...])",
        },
        { regex: /\bcowboy_req:(?:binding|qs|read_body|header)\b/, label: "cowboy_req accessor" },
      ],
      content,
    );
  },
};

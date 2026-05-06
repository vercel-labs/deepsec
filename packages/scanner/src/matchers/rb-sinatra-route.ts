import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const rbSinatraRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "rb-sinatra-route",
  description: "Sinatra route blocks (gated on Sinatra)",
  filePatterns: ["**/*.rb"],
  requires: { tech: ["sinatra"] },
  examples: [
    `get '/users' do`,
    `post "/login" do`,
    `put '/items/:id' do`,
    `patch "/profile" do`,
    `delete '/sessions/:id' do`,
    `options "/api" do`,
    `head '/healthz' do`,
    `before do`,
    `  halt 401, 'unauthorized'`,
    `name = params[:name]`,
  ],
  match(content, filePath) {
    if (/\b(?:test|spec)\b/i.test(filePath)) return [];

    return regexMatcher(
      "rb-sinatra-route",
      [
        {
          regex: /^\s*(?:get|post|put|patch|delete|options|head)\s+['"][^'"]+['"]\s+do\b/m,
          label: "Sinatra <verb> '/path' do ... end",
        },
        { regex: /^\s*before\s+do\b/m, label: "before do — auth filter" },
        { regex: /^\s*halt\s+\d+/m, label: "halt — auth response" },
        { regex: /\bparams\[/, label: "params[:x] (untrusted input)" },
      ],
      content,
    );
  },
};

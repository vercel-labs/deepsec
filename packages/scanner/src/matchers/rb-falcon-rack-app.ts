import type { MatcherPlugin } from "../types.js";
import {
  isSkippableRubyGeneratedFile,
  regexMatcher,
  rubyGemfileHas,
  rubyLockfileHas,
} from "./utils.js";

function hasFalconRubySentinel(filePath: string, content: string): boolean {
  return (
    filePath.endsWith(".ru") ||
    rubyGemfileHas(content, "falcon") ||
    rubyLockfileHas(content, "falcon")
  );
}

export const rbFalconRackAppMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "rb-falcon-rack-app",
  description: "Ruby Falcon / async Rack app bootstrap surfaces (gated on Falcon)",
  filePatterns: ["**/*.rb", "**/*.ru"],
  requires: {
    tech: ["falcon-ruby"],
    sentinelFiles: ["**/Gemfile", "**/Gemfile.lock", "**/*.ru"],
    sentinelContains: hasFalconRubySentinel,
  },
  examples: [
    `require "falcon"`,
    `service = Falcon::Service.new`,
    `endpoint = Async::HTTP::Endpoint.parse(url)`,
    `container = Async::Container.new`,
    `service = Async::Service.new`,
  ],
  match(content, filePath) {
    if (isSkippableRubyGeneratedFile(filePath, content)) return [];

    return regexMatcher(
      "rb-falcon-rack-app",
      [
        { regex: /require\s+["']falcon["']/, label: "require 'falcon'" },
        { regex: /\bFalcon::\w+/, label: "Falcon::* app/server surface" },
        {
          regex: /\bAsync::(?:HTTP|Container|Service)\b/,
          label: "Async HTTP/container/service bootstrap",
        },
      ],
      content,
    );
  },
};

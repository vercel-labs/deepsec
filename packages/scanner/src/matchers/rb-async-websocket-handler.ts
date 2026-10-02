import type { MatcherPlugin } from "../types.js";
import {
  isSkippableRubyGeneratedFile,
  regexMatcher,
  rubyGemfileHas,
  rubyLockfileHas,
} from "./utils.js";

function hasAsyncWebSocketSentinel(_path: string, content: string): boolean {
  return rubyGemfileHas(content, "async-websocket") || rubyLockfileHas(content, "async-websocket");
}

export const rbAsyncWebSocketHandlerMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "rb-async-websocket-handler",
  description: "Ruby async-websocket handlers and message loops (gated on async-websocket)",
  filePatterns: ["**/*.rb", "**/*.ru"],
  requires: {
    tech: ["async-websocket"],
    sentinelFiles: ["**/Gemfile", "**/Gemfile.lock"],
    sentinelContains: hasAsyncWebSocketSentinel,
  },
  examples: [
    `Async::WebSocket::Adapters::Rack.open(env) do |connection|`,
    `message = connection.read`,
    `payload = message.buffer`,
    `while message = connection.read`,
  ],
  match(content, filePath) {
    if (isSkippableRubyGeneratedFile(filePath, content)) return [];

    return regexMatcher(
      "rb-async-websocket-handler",
      [
        {
          regex: /\bAsync::WebSocket::Adapters::Rack\.open\b/,
          label: "Async::WebSocket::Adapters::Rack.open handler",
        },
        { regex: /\bconnection\.read\b/, label: "connection.read message receive" },
        { regex: /\bmessage\.buffer\b/, label: "message.buffer untrusted payload" },
        {
          regex: /while\s+\w+\s*=\s*connection\.read\b/,
          label: "websocket read loop",
        },
      ],
      content,
    );
  },
};

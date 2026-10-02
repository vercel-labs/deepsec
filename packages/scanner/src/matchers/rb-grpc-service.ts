import type { MatcherPlugin } from "../types.js";
import {
  isSkippableRubyGeneratedFile,
  regexMatcher,
  rubyGemfileHas,
  rubyLockfileHas,
} from "./utils.js";

function hasGrpcRubySentinel(_path: string, content: string): boolean {
  return (
    rubyGemfileHas(content, "grpc") ||
    rubyGemfileHas(content, "async-grpc") ||
    rubyLockfileHas(content, "grpc") ||
    rubyLockfileHas(content, "async-grpc")
  );
}

export const rbGrpcServiceMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "rb-grpc-service",
  description: "Ruby gRPC service implementations and interceptors (gated on grpc/async-grpc)",
  filePatterns: ["**/*.rb"],
  requires: {
    tech: ["grpc-ruby", "async-grpc"],
    sentinelFiles: ["**/Gemfile", "**/Gemfile.lock"],
    sentinelContains: hasGrpcRubySentinel,
  },
  examples: [
    `class GreeterServer < Helloworld::Greeter::Service`,
    `include GRPC::GenericService`,
    `rpc :Lookup, LookupRequest, LookupResponse`,
    `def lookup(request, call)`,
    `token = call.metadata["authorization"]`,
    `class AuthInterceptor < GRPC::ServerInterceptor`,
    `def request_response(request: nil, call: nil, method: nil)`,
    `server.add_http2_port("0.0.0.0:50051", :this_port_is_insecure)`,
    `server.handle(ExampleService)`,
    `server.run_till_terminated`,
  ],
  match(content, filePath) {
    if (isSkippableRubyGeneratedFile(filePath, content)) return [];

    return regexMatcher(
      "rb-grpc-service",
      [
        {
          regex: /^\s*class\s+\w+(?:::\w+)*\s*<\s*(?:::)?[\w:]+::Service\b/m,
          label: "Ruby gRPC service implementation subclass",
        },
        { regex: /\bGRPC::GenericService\b/, label: "GRPC::GenericService definition" },
        { regex: /^\s*rpc\s+:\w+/m, label: "rpc :Method declaration" },
        {
          regex: /^\s*def\s+\w+[!?]?\s*\(\s*\w+\s*,\s*_?call\s*\)/m,
          label: "RPC method(request, call)",
        },
        { regex: /\bcall\.metadata\b/, label: "call.metadata auth/header boundary" },
        { regex: /\bGRPC::ServerInterceptor\b/, label: "GRPC::ServerInterceptor" },
        {
          regex: /^\s*def\s+(?:request_response|client_streamer|server_streamer|bidi_streamer)\b/m,
          label: "gRPC interceptor hook",
        },
        {
          regex: /\bserver\.handle\b|\b(?:add_http2_port|run_till_terminated)\b/,
          label: "gRPC server bootstrap",
        },
      ],
      content,
    );
  },
};

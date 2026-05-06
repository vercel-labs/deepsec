import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const rsTonicGrpcMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "rs-tonic-grpc",
  description: "Tonic gRPC service implementations (gated on Tonic)",
  filePatterns: ["**/*.rs"],
  requires: { tech: ["tonic"] },
  examples: [
    `#[tonic::async_trait]`,
    `#[ tonic::async_trait ]`,
    `impl Greeter for MyGreeter {`,
    `impl UserService for UserServiceImpl {`,
    `async fn say_hello(&self, request: Request<HelloRequest>) -> Result<Response<HelloReply>, Status> {`,
    `let response: Response<UserReply> = ...;`,
    `return Err(Status::unauthenticated("missing token"));`,
    `Status::permission_denied("forbidden")`,
    `Status::invalid_argument("bad input")`,
  ],
  match(content, filePath) {
    if (/\/(tests|examples)\//.test(filePath)) return [];

    return regexMatcher(
      "rs-tonic-grpc",
      [
        { regex: /#\[\s*tonic::async_trait\s*\]/, label: "#[tonic::async_trait] impl" },
        {
          regex: /\bimpl\s+\w+\s+for\s+\w+\s*\{/,
          label: "service trait implementation",
        },
        { regex: /\bRequest<[^>]+>|\bResponse<[^>]+>/, label: "Request/Response shape" },
        {
          regex: /\bStatus::(?:unauthenticated|permission_denied|invalid_argument)/,
          label: "Status response",
        },
      ],
      content,
    );
  },
};

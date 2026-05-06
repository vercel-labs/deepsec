import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Wide-net matcher: any Go file that *implements* a ConnectRPC handler
 * method, identified by the receiver-method signature
 *
 *   func (s *X) Method(ctx context.Context, req *connect.Request[T]) (*connect.Response[U], error)
 *
 * or the streaming variants (`*connect.ClientStream`, `*connect.ServerStream`).
 *
 * This catches handler bodies regardless of whether they trigger the more
 * specific path/exec/trust matchers — every handler on a server-side mux
 * is an entry point and deserves an AI read.
 */
export const connectrpcHandlerImplMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "connectrpc-handler-impl",
  description: "Go file implementing one or more ConnectRPC handler methods (entry-point surface)",
  filePatterns: ["**/*.go"],
  requires: { tech: ["connectrpc"] },
  examples: [
    `func (s *Service) ExecCommand(ctx context.Context, req *connect.Request[ExecRequest]) (*connect.Response[ExecResponse], error) {\n  return nil, nil\n}`,
    `func (cs *ControllerService) Run(\n  ctx context.Context,\n  req *connect.Request[RunRequest],\n) (*connect.Response[RunResponse], error) {\n  return nil, nil\n}`,
    `func (s *Server) Stream(ctx context.Context, stream *connect.ServerStream[Event]) error {\n  return nil\n}`,
    `func (h *Handler) BidiChat(ctx context.Context, stream *connect.BidiStream[Msg, Msg]) error {\n  return nil\n}`,
    `func (s *Service) Upload(ctx context.Context, stream *connect.ClientStream[Chunk]) (*connect.Response[Ack], error) {\n  return nil, nil\n}`,
  ],
  match(content, filePath) {
    if (/_test\.go$/.test(filePath)) return [];
    if (/(?:^|\/)gen\//.test(filePath)) return [];

    const lines = content.split("\n");
    const hitLines: number[] = [];
    let firstContext: string | undefined;

    // Method definitions can span multiple lines:
    //   func (cs *ControllerService) ExecCommand(
    //     ctx context.Context,
    //     req *connect.Request[sandbox.ExecCommandRequest],
    //   ) (*connect.Response[sandbox.ExecCommandResponse], error) {
    //
    // We anchor on a top-level `func (...) Method(` line, then scan up to
    // the next 6 lines for `context.Context` AND `connect.Request|...`.
    const FUNC_OPEN = /^\s*func\s*\([^)]+\)\s+[A-Z]\w*\s*\(/;
    const CONNECT_TYPE = /\bconnect\.(?:Request|ClientStream|BidiStream|ServerStream)\b/;

    for (let i = 0; i < lines.length; i++) {
      if (!FUNC_OPEN.test(lines[i])) continue;
      const span = lines.slice(i, i + 8).join("\n");
      if (!/\bcontext\.Context\b/.test(span)) continue;
      if (!CONNECT_TYPE.test(span)) continue;
      hitLines.push(i + 1);
      if (firstContext === undefined) {
        const s = Math.max(0, i - 1);
        const e = Math.min(lines.length, i + 7);
        firstContext = lines.slice(s, e).join("\n");
      }
    }

    if (hitLines.length === 0) return [];
    const match: CandidateMatch = {
      vulnSlug: "connectrpc-handler-impl",
      lineNumbers: hitLines,
      snippet: firstContext ?? "",
      matchedPattern: "ConnectRPC handler method body",
    };
    return [match];
  },
};

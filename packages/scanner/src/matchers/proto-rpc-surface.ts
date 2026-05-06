import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Wide-net matcher: every `.proto` file that declares a `service` block.
 * Each `rpc` method is a wire-level entry point — request and response
 * messages constrain what the implementation can be asked to do, and what
 * it returns to peers. Reading the proto first orients an AI reviewer.
 *
 * Also flags message/enum-only proto files (no service) that define types
 * carrying user-controllable data (paths, URLs, args, env, modes), since
 * those types frequently end up in `os.*` / `syscall.*` / `exec.*` calls
 * on the host side.
 */
export const protoRpcSurfaceMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "proto-rpc-surface",
  description: "Protobuf service or message file (RPC entry point / wire-format definition)",
  filePatterns: ["**/*.proto"],
  requires: { tech: ["grpc", "connectrpc"] },
  examples: [
    `service ControllerService {\n  rpc ExecCommand(ExecRequest) returns (ExecResponse);\n}`,
    `service Sandbox {\n  rpc Run(RunRequest) returns (RunResponse);\n  rpc Stream(StreamRequest) returns (stream Event);\n}`,
    `message ExecRequest {\n  string command = 1;\n  repeated string args = 2;\n  string path = 3;\n}`,
    `message FileOp {\n  string source = 1;\n  string destination = 2;\n  uint32 mode = 3;\n}`,
    `message Image {\n  string url = 1;\n  string digest = 2;\n}`,
    `enum Mode {\n  MODE_UNSPECIFIED = 0;\n  MODE_RW = 1;\n}`,
  ],
  match(content) {
    const lines = content.split("\n");
    const hitLines: number[] = [];
    const labels = new Set<string>();
    let firstContext: string | undefined;

    const PATTERNS: { regex: RegExp; label: string }[] = [
      { regex: /^\s*service\s+\w+\s*\{/, label: "service block" },
      { regex: /^\s*rpc\s+\w+\s*\(/, label: "rpc method" },
      // Sensitive field names that often carry untrusted user input
      {
        regex:
          /\b(?:source|destination|path|target_path|source_url|url|digest|command|arguments|args|env|environment|mode|owner|group|uid|gid|key_id|kernel_args|rootfs|cmdline)\s*=\s*\d+\s*;/,
        label: "sensitive field",
      },
    ];

    for (let i = 0; i < lines.length; i++) {
      for (const { regex, label } of PATTERNS) {
        if (regex.test(lines[i])) {
          hitLines.push(i + 1);
          labels.add(label);
          if (firstContext === undefined) {
            const s = Math.max(0, i - 2);
            const e = Math.min(lines.length, i + 3);
            firstContext = lines.slice(s, e).join("\n");
          }
          break;
        }
      }
    }

    // Always-flag fallback for proto files: even pure message/enum
    // definitions (no service block) are part of the wire format and worth
    // a security read for guest-controlled fields.
    if (hitLines.length === 0) {
      const firstMessage = lines.findIndex((l) => /^\s*(?:message|enum)\s+\w+/.test(l));
      if (firstMessage === -1) return [];
      const s = Math.max(0, firstMessage - 1);
      const e = Math.min(lines.length, firstMessage + 4);
      const match: CandidateMatch = {
        vulnSlug: "proto-rpc-surface",
        lineNumbers: [firstMessage + 1],
        snippet: lines.slice(s, e).join("\n"),
        matchedPattern: "proto message/enum (no service block)",
      };
      return [match];
    }
    const match: CandidateMatch = {
      vulnSlug: "proto-rpc-surface",
      lineNumbers: hitLines,
      snippet: firstContext ?? "",
      matchedPattern: Array.from(labels).slice(0, 3).join(", "),
    };
    return [match];
  },
};

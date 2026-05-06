import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Unix-domain socket / vsock listener setup, with surrounding context
 * (umask, permission, auto-recreate loops, parent-dir trust assumptions).
 *
 * Specific concerns surfaced by AI review:
 *   - Auto-recreate on socket-file deletion can attach to an attacker-planted
 *     symlink under the same name if the parent dir is not exclusive.
 *   - `syscall.Umask` set just before Listen but not re-set after = leaked
 *     process-wide perms while parallel goroutines create files.
 *   - Listening before chown'ing the parent dir = brief writable window.
 *   - Vsock/CID listeners with no per-CID auth = any guest can call.
 */
export const unixSocketListenerMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "unix-socket-listener",
  description: "Unix-socket / vsock listener setup (incl. umask + auto-recreate patterns)",
  filePatterns: ["**/*.go"],
  requires: { tech: ["go"] },
  examples: [
    `l, err := net.Listen("unix", "/var/run/app.sock")`,
    `l, err := net.Listen("unixpacket", path)`,
    `l, err := net.ListenUnix("unix", addr)`,
    `l, err := vsock.Listen(uint32(port), nil)`,
    `conn, err := vsock.Dial(cid, port, nil)`,
    `pc, err := net.ListenPacket("unix", path)`,
    `oldMask := syscall.Umask(0177)`,
    `os.Remove(socketPath)`,
    `watcher.Add("/var/run")`,
  ],
  match(content, filePath) {
    if (/_test\.go$/.test(filePath)) return [];
    if (/(?:^|\/)gen\//.test(filePath)) return [];

    const lines = content.split("\n");
    const hitLines: number[] = [];
    const labels = new Set<string>();
    let firstContext: string | undefined;

    const PATTERNS: { regex: RegExp; label: string }[] = [
      { regex: /\bnet\.Listen\s*\(\s*"unix(?:packet|gram)?"/, label: "net.Listen unix socket" },
      { regex: /\bnet\.ListenUnix\s*\(/, label: "net.ListenUnix" },
      { regex: /\bvsock\.(?:Listen|Dial|ListenContextID)\s*\(/, label: "vsock listener/dial" },
      { regex: /\bnet\.ListenPacket\s*\(\s*"unix/, label: "net.ListenPacket unix" },
      { regex: /\bsyscall\.Umask\s*\(/, label: "syscall.Umask (socket perm)" },
      { regex: /\bos\.(?:Remove|RemoveAll)\s*\([^)]*[Ss]ocket/, label: "socket file removal" },
      { regex: /\bfsnotify\.\w+|inotify\.|watcher\.Add\s*\(/, label: "filesystem watcher" },
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

    if (hitLines.length === 0) return [];
    const match: CandidateMatch = {
      vulnSlug: "unix-socket-listener",
      lineNumbers: hitLines,
      snippet: firstContext ?? "",
      matchedPattern: Array.from(labels).slice(0, 4).join(", "),
    };
    return [match];
  },
};

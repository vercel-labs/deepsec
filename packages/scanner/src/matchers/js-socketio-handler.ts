import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const jsSocketioHandlerMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "js-socketio-handler",
  description: "Socket.IO event handlers — entry-point surface (gated on socketio)",
  filePatterns: ["**/*.{ts,js,mjs,cjs}"],
  requires: { tech: ["socketio"] },
  examples: [
    `io.on('connection', (socket) => { console.log('hi') })`,
    `io.on("connection", socket => {})`,
    `socket.on('chat:message', (msg) => broadcast(msg))`,
    `socket.on("disconnect", () => {})`,
    `io.use((socket, next) => next())`,
    `const token = socket.handshake.auth.token`,
    `const ua = socket.handshake.headers["user-agent"]`,
    `const room = socket.handshake.query.room`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    return regexMatcher(
      "js-socketio-handler",
      [
        {
          regex: /\bio\.on\s*\(\s*['"]connection['"]/,
          label: "io.on('connection', ...) — connection entry",
        },
        {
          regex: /\bsocket\.on\s*\(\s*['"][^'"]+['"]/,
          label: "socket.on('event', handler)",
        },
        { regex: /\bio\.use\s*\(/, label: "io.use(authMiddleware) — auth gate" },
        {
          regex: /\bsocket\.handshake\.(?:auth|headers|query)\b/,
          label: "handshake.auth/headers/query (untrusted input)",
        },
      ],
      content,
    );
  },
};

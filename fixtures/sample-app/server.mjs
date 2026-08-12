// Dependency-free loopback server that serves the sample app's planted
// behaviors. The app/ tree is the extractor's ground truth; this server is the
// live target the probe runner hits. Run: node server.mjs [port]
//
// Planted behaviors (see expectations.json):
//   GET /api/health        -> 200, public, full security headers (control)
//   GET /api/profile       -> 401 anonymous, 200 with bearer token (auth required)
//   GET /api/public-info   -> 200 with data-shaped body, NO auth (exposure, unknown)
//   GET /api/users/:id     -> 200 for ANY authenticated user regardless of :id (IDOR)
//   GET /api/secure        -> 401 anonymous, 200 with full security headers when authed
//                             (the 401 challenge ALSO carries the full headers, so the
//                             M1 anonymous security-header probe sees the hardened posture)
//   GET /api/weak-headers  -> 200 with no security headers (header-posture finding)

import http from "node:http";

const TOKENS = {
  // Test identities for the two-identity differential (IDOR) and auth checks.
  "token-user-a": { userId: "user-a", email: "a@example.com" },
  "token-user-b": { userId: "user-b", email: "b@example.com" },
};

function sessionFor(req) {
  const auth = req.headers.authorization ?? "";
  const m = /^Bearer\s+(.+)$/.exec(auth);
  return m ? (TOKENS[m[1]] ?? null) : null;
}

// Shared hardened header set. Hoisted so the security-header control routes
// (/api/health, /api/secure) and the auth challenge share one definition.
const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "content-security-policy": "default-src 'none'",
  "strict-transport-security": "max-age=63072000",
};

const server = http.createServer((req, res) => {
  const url = new URL(req.url ?? "/", "http://localhost");
  const path = url.pathname;
  const send = (status, body, headers = {}) => {
    const payload = typeof body === "string" ? body : JSON.stringify(body);
    res.writeHead(status, { "content-type": "application/json", ...headers });
    res.end(payload);
  };

  if (path === "/api/health") {
    return send(200, { ok: true }, SECURITY_HEADERS);
  }

  if (path === "/api/profile") {
    const s = sessionFor(req);
    if (!s) return send(401, "Unauthorized");
    return send(200, { id: s.userId, email: s.email });
  }

  if (path === "/api/public-info") {
    // Exposure: no auth check at all.
    return send(200, { name: "deepsec sample", internal: true, version: "1.0.0" });
  }

  const userMatch = /^\/api\/users\/([^/]+)$/.exec(path);
  if (userMatch) {
    const s = sessionFor(req);
    if (!s) return send(401, "Unauthorized");
    // IDOR: returns the requested user's record regardless of who asked.
    return send(200, { id: userMatch[1], ssn: "000-00-0000", balance: 1000 });
  }

  if (path === "/api/secure") {
    const s = sessionFor(req);
    // Hardened posture applies to the auth challenge too: the M1 header
    // template probes anonymously and must observe the headers.
    if (!s) return send(401, "Unauthorized", SECURITY_HEADERS);
    return send(200, { ok: true }, SECURITY_HEADERS);
  }

  if (path === "/api/weak-headers") {
    // Header-posture finding: no security headers at all.
    return send(200, { ok: true });
  }

  return send(404, { error: "not found" });
});

const port = Number(process.argv[2] ?? process.env.PORT ?? 0);
server.listen(port, "127.0.0.1", () => {
  const addr = server.address();
  console.log(`sample-app listening on http://127.0.0.1:${addr.port}`);
});

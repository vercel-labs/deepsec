// Participates in the surface fingerprint (it can enforce auth edge-wide),
// though it is not itself a routable endpoint. Intentionally a no-op matcher.
export function middleware() {}

export const config = {
  matcher: ["/api/:path*"],
};

import { requireAuth } from "../../../lib/auth";

// Known-safe hardened route: requires auth and sets full security headers.
export async function GET() {
  const session = await requireAuth();
  if (!session) {
    return new Response("Unauthorized", { status: 401 });
  }
  return new Response(JSON.stringify({ ok: true }), {
    headers: {
      "content-type": "application/json",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "content-security-policy": "default-src 'none'",
      "strict-transport-security": "max-age=63072000",
    },
  });
}

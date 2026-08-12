/* @public */
// Planted header-posture finding: public and intentionally served without
// security headers, so the security-headers template fires on it.
export async function GET() {
  return Response.json({ ok: true });
}

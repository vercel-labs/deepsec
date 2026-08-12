// Known-safe, intentionally public health check.
/* @public */
export async function GET() {
  return Response.json({ ok: true });
}

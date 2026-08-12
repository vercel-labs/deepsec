import { requireAuth } from "../../../lib/auth";

// Known-safe: requires auth. An anonymous request must be rejected.
export async function GET() {
  const session = await requireAuth();
  if (!session) {
    return new Response("Unauthorized", { status: 401 });
  }
  return Response.json({ id: session.userId, email: session.email });
}

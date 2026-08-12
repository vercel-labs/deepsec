import { getSession } from "../../../../lib/auth";

// Planted tenant-isolation bug (IDOR): any authenticated user can read any
// other user's object — there is no check that session.userId === params.id.
export async function GET(_req: Request, { params }: { params: { id: string } }) {
  const session = await getSession();
  if (!session) {
    return new Response("Unauthorized", { status: 401 });
  }
  // BUG: no ownership check. user-a can read user-b's record.
  return Response.json({ id: params.id, ssn: "000-00-0000", balance: 1000 });
}

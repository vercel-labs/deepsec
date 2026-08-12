// Planted vulnerability: this route returns data-shaped content with NO auth
// check and NO explicit public marker, so the extractor infers `unknown`.
// An anonymous request returns 200 with data — the exposure the auth-expectation
// hunt should surface as a capped-severity candidate (never auto-confirmed).
export async function GET() {
  return Response.json({ name: "deepsec sample", internal: true, version: "1.0.0" });
}

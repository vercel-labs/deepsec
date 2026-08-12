// Minimal auth helpers for the sample app. The real behavior lives in the
// loopback server (server.mjs); these stubs exist so the extractor's
// auth-inference has recognizable signals in the route sources.

export interface Session {
  userId: string;
  email: string;
}

/** Returns the session for the current request, or null when anonymous. */
export async function getSession(): Promise<Session | null> {
  // Placeholder — the loopback server implements the actual token check.
  return null;
}

/** Like getSession but the route treats null as unauthorized. */
export async function requireAuth(): Promise<Session | null> {
  return getSession();
}

// Preflight checks run before we spin up sandboxes or agent SDKs.
//
// The motivation: when env vars are missing, the failure surfaces deep in
// upstream code — Anthropic SDK throws "API key not found" with no hint
// the issue is on the orchestrator host, the Vercel SDK errors look like
// auth problems somewhere remote, and the sandbox firewall happily emits
// `{ allow: { host: [] } }` with no transform rule so requests later 401
// from upstream as if it were a model issue. Each variant has cost the
// human time before, so we trade ~20 lines for a clear message up front.

import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { getVercelOidcToken } from "@vercel/oidc";

// Linkable URL — printed in error messages so users can paste the
// URL into a browser instead of hunting through the repo. Points at
// the rendered `main` version on github.com so it works whether the
// CLI was invoked from inside the source repo, from an installed
// package, or in CI.
const SETUP_DOC_URL = "https://github.com/vercel-labs/deepsec/blob/main/docs/vercel-setup.md";

// Vercel AI Gateway endpoints. The Anthropic adapter is at the root; the
// OpenAI-compatible adapter is at /v1 (codex appends /responses to it).
const GATEWAY_ANTHROPIC_BASE_URL = "https://ai-gateway.vercel.sh";
const GATEWAY_OPENAI_BASE_URL = "https://ai-gateway.vercel.sh/v1";

// Refresh the OIDC token if it would expire within the next hour. Bounds the
// risk that a token resolved at CLI startup expires mid-run — sandbox jobs
// and long process/revalidate runs routinely take longer than a few minutes,
// and the gateway will 401 the moment the JWT lapses.
const OIDC_EXPIRATION_BUFFER_MS = 60 * 60 * 1000;

/**
 * If the user set `AI_GATEWAY_API_KEY`, expand it into the four env vars
 * the agent SDKs actually read. Lets a user run with a single token
 * instead of duplicating it across `ANTHROPIC_AUTH_TOKEN` /
 * `OPENAI_API_KEY` (the gateway accepts the same token for both).
 *
 * Falls back to a Vercel OIDC token (via `@vercel/oidc`) when
 * `AI_GATEWAY_API_KEY` is unset. The AI Gateway accepts OIDC tokens
 * issued by `vercel env pull`, so a user who's already linked the project
 * doesn't need a separate gateway key. `getVercelOidcToken` also refreshes
 * the token in development when it's expired or near expiry.
 *
 * Existing values always win — this only fills in what's missing, so a
 * user who has set, say, `ANTHROPIC_BASE_URL=https://api.anthropic.com`
 * for direct-to-provider access doesn't get silently rerouted.
 *
 * Call this once at CLI startup (after dotenv loads .env.local), before
 * any module reads these vars.
 */
export async function applyAiGatewayDefaults(): Promise<void> {
  if (!process.env.AI_GATEWAY_API_KEY) {
    try {
      process.env.AI_GATEWAY_API_KEY = await getVercelOidcToken({
        expirationBufferMs: OIDC_EXPIRATION_BUFFER_MS,
      });
    } catch {
      // No OIDC token available (no env var, no linked project, or refresh
      // failed). Fall through — assertAgentCredential will emit a clearer
      // error pointing at .env.local if a credential is actually required.
    }
  }
  const key = process.env.AI_GATEWAY_API_KEY;
  if (!key) return;
  if (!process.env.ANTHROPIC_AUTH_TOKEN) process.env.ANTHROPIC_AUTH_TOKEN = key;
  if (!process.env.OPENAI_API_KEY) process.env.OPENAI_API_KEY = key;
  if (!process.env.ANTHROPIC_BASE_URL) process.env.ANTHROPIC_BASE_URL = GATEWAY_ANTHROPIC_BASE_URL;
  if (!process.env.OPENAI_BASE_URL) process.env.OPENAI_BASE_URL = GATEWAY_OPENAI_BASE_URL;
}

function isCodex(agentType: string | undefined): boolean {
  return agentType === "codex";
}

/**
 * Walk `$PATH` looking for a binary. Used as a positive signal that an
 * agent CLI (`claude`, `codex`) is set up on this host — if it's
 * installed, the user almost certainly logged in too, and the SDK will
 * use whatever auth that CLI manages (Keychain on macOS, file on Linux,
 * OAuth token env var, etc.). If they happen to be installed but not
 * logged in, the SDK errors clearly at first call — better than us
 * pre-blocking with a verbose pile of options.
 *
 * Synchronous PATH walk is cheap enough for preflight; using `execSync`
 * would also work but adds a fork.
 */
function whichSync(bin: string): boolean {
  const pathEnv = process.env.PATH || "";
  const sep = process.platform === "win32" ? ";" : ":";
  for (const dir of pathEnv.split(sep)) {
    if (!dir) continue;
    if (existsSync(join(dir, bin))) return true;
    if (process.platform === "win32") {
      if (existsSync(join(dir, `${bin}.exe`))) return true;
      if (existsSync(join(dir, `${bin}.cmd`))) return true;
    }
  }
  return false;
}

/**
 * "Likely to just work" signal for the Claude subscription path. The
 * Claude Agent SDK spawns the `claude` CLI as a subprocess; if that
 * binary is on PATH the SDK can use whatever auth it manages (Keychain
 * on macOS, ~/.claude/.credentials.json on Linux, CLAUDE_CODE_OAUTH_TOKEN
 * env var). We don't try to verify the user is actually logged in — if
 * not, the SDK's own error at first call is clearer than ours.
 *
 * Only consulted in non-sandbox runs. The sandbox worker VM has no
 * claude binary, so this helper is irrelevant there.
 */
function hasLocalClaudeAgent(): boolean {
  return whichSync("claude");
}

/**
 * Same idea for Codex, but stricter: codex-sdk.ts mirrors the user's
 * `auth.json` into a per-invocation tempdir, so we need that file to
 * actually exist. `which codex` alone isn't enough — a logged-out
 * codex CLI would fall through to gateway mode without an API key and
 * 401. Honors `CODEX_HOME`.
 */
function hasLocalCodexAgent(): boolean {
  const codexHome = process.env.CODEX_HOME || join(homedir(), ".codex");
  return existsSync(join(codexHome, "auth.json"));
}

// Built-in backends we know how to credential-check. Agents registered
// via plugins (deepsec.config.ts → plugins: [{ agents: [...] }]) handle
// their own credential resolution, so we skip the check for anything
// other than these.
const KNOWN_BACKENDS = new Set<string>(["claude-agent-sdk", "codex"]);

/**
 * Verify the orchestrator has an AI credential the chosen agent can use.
 * Throws with a concrete pointer at .env.local when it doesn't — the
 * sandbox path brokers credentials via firewall header injection, but
 * that only works if the orchestrator actually has a token to inject.
 *
 * Pass `inSandbox: true` from sandbox commands. Subscription auth (a
 * local `claude login`) is only honored when this is false — the
 * sandbox worker has no `claude` CLI and no Keychain, so it must ship a
 * real API token through the firewall header rewrite.
 *
 * Skipped for plugin-supplied agents (`agentType` not in `KNOWN_BACKENDS`):
 * those backends own their credential story. Tests use this to plug in a
 * stub agent without setting fake env vars.
 */
export function assertAgentCredential(
  agentType: string | undefined,
  options: { inSandbox?: boolean } = {},
): void {
  if (agentType !== undefined && !KNOWN_BACKENDS.has(agentType)) return;

  const anthropic = process.env.ANTHROPIC_AUTH_TOKEN;
  const openai = process.env.OPENAI_API_KEY;

  if (isCodex(agentType)) {
    // Codex prefers OPENAI_API_KEY; AI Gateway issues a single token that
    // authenticates both backends, so an ANTHROPIC token is also accepted.
    if (openai || anthropic) return;
    if (!options.inSandbox && hasLocalCodexAgent()) return;
    throw new Error(
      `Missing AI credentials for --agent codex.\n` +
        `\n` +
        `  Add to .env.local:    AI_GATEWAY_API_KEY=vck_…   (or OPENAI_API_KEY=…)\n` +
        `  Setup: ${SETUP_DOC_URL}`,
    );
  }

  if (anthropic) return;
  if (!options.inSandbox && hasLocalClaudeAgent()) return;
  throw new Error(
    `Missing AI credentials for --agent ${agentType ?? "claude-agent-sdk"}.\n` +
      `\n` +
      `  Add to .env.local:    AI_GATEWAY_API_KEY=vck_…   (or ANTHROPIC_AUTH_TOKEN=…)\n` +
      `  Setup: ${SETUP_DOC_URL}`,
  );
}

/**
 * Verify the orchestrator has Vercel Sandbox credentials. Inside a Vercel
 * deployment OIDC is automatic; locally the user runs `vercel link` +
 * `vercel env pull` to land VERCEL_OIDC_TOKEN in .env.local, OR sets the
 * three explicit access-token env vars.
 */
export function assertSandboxCredential(): void {
  const oidc = process.env.VERCEL_OIDC_TOKEN;
  if (oidc) return;

  const token = process.env.VERCEL_TOKEN;
  const teamId = process.env.VERCEL_TEAM_ID;
  const projectId = process.env.VERCEL_PROJECT_ID;
  if (token && teamId && projectId) return;

  const missing: string[] = [];
  if (!token) missing.push("VERCEL_TOKEN");
  if (!teamId) missing.push("VERCEL_TEAM_ID");
  if (!projectId) missing.push("VERCEL_PROJECT_ID");

  throw new Error(
    `Missing Vercel Sandbox credentials.\n` +
      `\n` +
      `  Recommended: run these to populate VERCEL_OIDC_TOKEN in .env.local:\n` +
      `\n` +
      `      npx vercel link\n` +
      `      npx vercel env pull\n` +
      `\n` +
      `  Alternative — access-token mode: set ${missing.join(", ")}.\n` +
      `\n` +
      `  Full setup: ${SETUP_DOC_URL}`,
  );
}

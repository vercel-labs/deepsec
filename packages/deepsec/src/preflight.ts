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
import { getConfig } from "@deepsec/core";
import { getVercelOidcToken } from "@vercel/oidc";
import {
  applyResolvedModelRoute,
  type ModelRoute,
  modelRouteCompatibilityError,
  type ResolvedModelRoute,
  resolveModelRoute,
} from "./auth/model-route.js";

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

// Keep provenance for values synthesized during CLI startup. A later local
// subscription selection needs to undo only this ambient Gateway expansion,
// never values the user supplied or changed themselves.
const injectedAiGatewayDefaults = new Map<string, string>();

function injectAiGatewayDefault(name: string, value: string): void {
  if (process.env[name]) return;
  process.env[name] = value;
  injectedAiGatewayDefaults.set(name, value);
}

/**
 * If the user set `AI_GATEWAY_API_KEY`, expand it into the four env vars
 * the agent SDKs actually read. Lets a user run with a single token
 * instead of duplicating it across `ANTHROPIC_AUTH_TOKEN` /
 * `OPENAI_API_KEY` (the gateway accepts the same token for both).
 *
 * Falls back to a Vercel OIDC token (via `@vercel/oidc`) when
 * `AI_GATEWAY_API_KEY` is unset *and* `VERCEL_OIDC_TOKEN` is already in env
 * (typically populated by `vercel env pull`). The presence of the env var
 * is the user's opt-in: without it we never invoke `@vercel/oidc`, because
 * the library's refresh path walks up the directory tree from `cwd` looking
 * for a parent `.vercel/project.json` and would otherwise silently mint a
 * gateway token against an unrelated linked project (issue: a user with a
 * `.vercel/` two dirs up gets billed without realizing the gateway is in
 * play). With the gate, the token is taken from env and only the library's
 * near-expiry refresh ever touches the linked project — and only on a
 * project the user already authenticated against.
 *
 * Existing values always win — this only fills in what's missing, so a
 * user who has set, say, `ANTHROPIC_BASE_URL=https://api.anthropic.com`
 * for direct-to-provider access doesn't get silently rerouted.
 *
 * Call this once at CLI startup (after dotenv loads .env.local), before
 * any module reads these vars.
 */
export async function applyAiGatewayDefaults(): Promise<void> {
  for (const [name, injectedValue] of injectedAiGatewayDefaults) {
    if (process.env[name] !== injectedValue) injectedAiGatewayDefaults.delete(name);
  }
  if (!process.env.AI_GATEWAY_API_KEY && process.env.VERCEL_OIDC_TOKEN) {
    try {
      const key = await getVercelOidcToken({
        expirationBufferMs: OIDC_EXPIRATION_BUFFER_MS,
      });
      injectAiGatewayDefault("AI_GATEWAY_API_KEY", key);
    } catch {
      // Refresh failed (token unparseable, network, or the linked project
      // it would refresh against is gone). Fall through — assertAgentCredential
      // will emit a clearer error pointing at .env.local if a credential is
      // actually required.
    }
  }
  const key = process.env.AI_GATEWAY_API_KEY;
  if (!key) return;
  injectAiGatewayDefault("ANTHROPIC_AUTH_TOKEN", key);
  injectAiGatewayDefault("OPENAI_API_KEY", key);
  injectAiGatewayDefault("ANTHROPIC_BASE_URL", GATEWAY_ANTHROPIC_BASE_URL);
  injectAiGatewayDefault("OPENAI_BASE_URL", GATEWAY_OPENAI_BASE_URL);
}

/**
 * Stop ambient OIDC from overriding an explicit local-subscription route.
 * Sandbox commands are intentionally exempt: local machine credentials are
 * unavailable in the worker, so the startup-expanded token must be brokered.
 */
export function reconcileAiGatewayDefaultsForRoute(
  route: ModelRoute,
  options: { env?: NodeJS.ProcessEnv; inSandbox?: boolean } = {},
): void {
  if (route.mode !== "local" || options.inSandbox) return;
  const env = options.env ?? process.env;
  for (const [name, injectedValue] of injectedAiGatewayDefaults) {
    // A value changed since startup belongs to the user or selected route.
    if (env[name] === injectedValue) delete env[name];
  }
}

/**
 * Expand only the explicitly selected model route. Unlike the legacy gateway
 * helper, this never lets ambient OIDC redirect a direct/custom provider.
 */
export async function applySelectedModelRoute(
  route: ModelRoute,
  agentType: string,
  env: NodeJS.ProcessEnv = process.env,
): Promise<ResolvedModelRoute> {
  const resolved = await resolveModelRoute(route, { agentType, env });
  applyResolvedModelRoute(resolved, env);
  return resolved;
}

/** Rehydrate the non-secret model route persisted by one-shot setup. */
export async function applyConfiguredModelRoute(
  agentType: string,
  env: NodeJS.ProcessEnv = process.env,
  options: { inSandbox?: boolean } = {},
): Promise<ResolvedModelRoute | undefined> {
  const route = getConfig()?.ai as ModelRoute | undefined;
  if (!route) return undefined;
  // A persisted route is a default, not an explicit command-line request.
  // Preserve the pre-onboarding behavior for cross-agent invocations by
  // falling back to that harness's normal credential discovery.
  if (modelRouteCompatibilityError(route, agentType)) return undefined;
  // Local model auth comes from the machine-wide claude/codex/pi login. Undo
  // ambient Gateway values synthesized from OIDC, except in sandboxes where
  // the token still has to be brokered into the remote worker.
  if (route.mode === "local") {
    reconcileAiGatewayDefaultsForRoute(route, { env, inSandbox: options.inSandbox });
    return undefined;
  }
  // Older scaffold-only workspaces persisted Gateway as a default even when
  // the user intended to rely on a logged-in Codex/Claude/Pi subscription.
  // With no explicit Gateway credential, leave env untouched and let the
  // normal subscription-aware credential check decide whether the command can
  // proceed.
  if (route.mode === "gateway" && !env.AI_GATEWAY_API_KEY && !env.VERCEL_OIDC_TOKEN) {
    return undefined;
  }
  return applySelectedModelRoute(route, agentType, env);
}

function isCodex(agentType: string | undefined): boolean {
  return agentType === "codex";
}

function isPi(agentType: string | undefined): boolean {
  return agentType === "pi";
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

function hasLocalPiAgent(): boolean {
  const piHome = process.env.PI_CODING_AGENT_DIR || join(homedir(), ".pi", "agent");
  return existsSync(join(piHome, "auth.json"));
}

// Built-in backends we know how to credential-check. Agents registered
// via plugins (deepsec.config.ts → plugins: [{ agents: [...] }]) handle
// their own credential resolution, so we skip the check for anything
// other than these.
const KNOWN_BACKENDS = new Set<string>(["claude-agent-sdk", "codex", "pi"]);

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
  options: { inSandbox?: boolean; aiApiKeyEnv?: string; modelRoute?: ModelRoute } = {},
): void {
  if (agentType !== undefined && !KNOWN_BACKENDS.has(agentType)) return;

  // A local-subscription route is the user saying "claude/codex are set up
  // machine-wide" — skip the env-var checks entirely and let the agent SDK
  // error clearly at first call if the login is actually missing. Sandboxes
  // are the exception: they must broker a real token through the firewall,
  // so fall through to the normal checks (an ambient AI_GATEWAY_API_KEY
  // still works there, and the standard actionable error fires otherwise).
  const selectedRoute = options.modelRoute ?? (getConfig()?.ai as ModelRoute | undefined);
  if (selectedRoute?.mode === "local" && !options.inSandbox) return;

  const gateway = process.env.AI_GATEWAY_API_KEY;
  const anthropic = process.env.ANTHROPIC_AUTH_TOKEN;
  const anthropicApi = process.env.ANTHROPIC_API_KEY;
  const openai = process.env.OPENAI_API_KEY;
  const custom = options.aiApiKeyEnv ? process.env[options.aiApiKeyEnv] : undefined;

  // A selected route has already made precedence explicit. In particular,
  // direct Anthropic uses ANTHROPIC_API_KEY and its x-api-key broker contract;
  // ambient Gateway/OIDC must not be considered as a fallback.
  if (options.modelRoute && options.modelRoute.mode !== "local") {
    const keyEnv =
      options.modelRoute.apiKeyEnv ??
      (options.modelRoute.mode === "gateway"
        ? "AI_GATEWAY_API_KEY"
        : options.modelRoute.provider === "anthropic"
          ? "ANTHROPIC_API_KEY"
          : "OPENAI_API_KEY");
    if (process.env[keyEnv]) return;
    throw new Error(`Selected ${options.modelRoute.provider} model route requires ${keyEnv}`);
  }

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

  if (isPi(agentType)) {
    if (gateway || custom) return;
    if (!options.inSandbox && (anthropic || anthropicApi || openai || hasLocalPiAgent())) return;
    const customHint = options.aiApiKeyEnv
      ? `, or set ${options.aiApiKeyEnv}=… for the selected --ai-api-key-env`
      : "";
    throw new Error(
      `Missing AI credentials for --agent pi.\n` +
        `\n` +
        `  Add to .env.local:    AI_GATEWAY_API_KEY=vck_…${customHint}\n` +
        `  Setup: ${SETUP_DOC_URL}`,
    );
  }

  if (anthropic || anthropicApi) return;
  if (!options.inSandbox && hasLocalClaudeAgent()) return;
  const displayAgent =
    agentType === "claude-agent-sdk" || agentType === undefined ? "claude" : agentType;
  throw new Error(
    `Missing AI credentials for --agent ${displayAgent}.\n` +
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
export function assertSandboxCredential(options: { env?: NodeJS.ProcessEnv } = {}): void {
  const env = options.env ?? process.env;
  const oidc = env.VERCEL_OIDC_TOKEN;
  if (oidc) return;

  const token = env.VERCEL_TOKEN;
  const teamId = env.VERCEL_TEAM_ID;
  const projectId = env.VERCEL_PROJECT_ID;
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

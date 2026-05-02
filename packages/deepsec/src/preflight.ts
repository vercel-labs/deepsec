// Preflight checks run before we spin up sandboxes or agent SDKs.
//
// The motivation: when env vars are missing, the failure surfaces deep in
// upstream code — Anthropic SDK throws "API key not found" with no hint
// the issue is on the orchestrator host, the Vercel SDK errors look like
// auth problems somewhere remote, and the sandbox firewall happily emits
// `{ allow: { host: [] } }` with no transform rule so requests later 401
// from upstream as if it were a model issue. Each variant has cost the
// human time before, so we trade ~20 lines for a clear message up front.

const SETUP_DOC = "docs/vercel-setup.md";

// Vercel AI Gateway endpoints. The Anthropic adapter is at the root; the
// OpenAI-compatible adapter is at /v1 (codex appends /responses to it).
const GATEWAY_ANTHROPIC_BASE_URL = "https://ai-gateway.vercel.sh";
const GATEWAY_OPENAI_BASE_URL = "https://ai-gateway.vercel.sh/v1";

/**
 * If the user set `AI_GATEWAY_API_KEY`, expand it into the four env vars
 * the agent SDKs actually read. Lets a user run with a single token
 * instead of duplicating it across `ANTHROPIC_AUTH_TOKEN` /
 * `OPENAI_API_KEY` (the gateway accepts the same token for both).
 *
 * Existing values always win — this only fills in what's missing, so a
 * user who has set, say, `ANTHROPIC_BASE_URL=https://api.anthropic.com`
 * for direct-to-provider access doesn't get silently rerouted.
 *
 * Call this once at CLI startup (after dotenv loads .env.local), before
 * any module reads these vars.
 */
export function applyAiGatewayDefaults(): void {
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
 * Verify the orchestrator has an AI credential the chosen agent can use.
 * Throws with a concrete pointer at .env.local when it doesn't — the
 * sandbox path brokers credentials via firewall header injection, but
 * that only works if the orchestrator actually has a token to inject.
 */
export function assertAgentCredential(agentType: string | undefined): void {
  const anthropic = process.env.ANTHROPIC_AUTH_TOKEN;
  const openai = process.env.OPENAI_API_KEY;

  if (isCodex(agentType)) {
    // Codex prefers OPENAI_API_KEY; AI Gateway issues a single token that
    // authenticates both backends, so an ANTHROPIC token is also accepted.
    if (openai || anthropic) return;
    throw new Error(
      `Missing AI credentials for --agent codex.\n` +
        `  Set OPENAI_API_KEY (preferred) or ANTHROPIC_AUTH_TOKEN in .env.local.\n` +
        `  See ${SETUP_DOC} for AI Gateway setup.`,
    );
  }

  if (anthropic) return;
  throw new Error(
    `Missing AI credentials for --agent ${agentType ?? "claude-agent-sdk"}.\n` +
      `  Set ANTHROPIC_AUTH_TOKEN in .env.local.\n` +
      `  See ${SETUP_DOC} for AI Gateway setup.`,
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
      `  Recommended: run \`npx vercel link\` then \`npx vercel env pull\` to\n` +
      `  populate VERCEL_OIDC_TOKEN in .env.local.\n` +
      `  Alternative: set ${missing.join(", ")} (access-token mode).\n` +
      `  See ${SETUP_DOC}.`,
  );
}

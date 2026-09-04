import { getVercelOidcToken } from "@vercel/oidc";

export type ModelAuthMode = "gateway" | "direct" | "custom" | "local";
export type CredentialHeaderScheme = "bearer" | "raw";

export interface ModelRoute {
  mode: ModelAuthMode;
  provider: string;
  apiKeyEnv?: string;
  baseUrl?: string;
  /** Required for custom routes. Contains no secret. */
  credentialHeader?: { name: string; scheme: CredentialHeaderScheme };
  /** Backward-compatible flat spelling used by early config scaffolds. */
  authHeader?: string;
  authScheme?: CredentialHeaderScheme;
}

export interface BrokeredModelCredential {
  host: string;
  placeholderEnv: string;
  header: { name: string; value: string };
}

export interface ResolvedModelRoute {
  route: ModelRoute;
  credentialEnv: string;
  /** Host-side only. Never serialize this result into setup state. */
  credential: string;
  environment: Record<string, string>;
  broker: BrokeredModelCredential;
}

export interface ResolveModelRouteOptions {
  agentType: string;
  env?: NodeJS.ProcessEnv;
  getOidcToken?: typeof getVercelOidcToken;
  vercelTeam?: string;
  vercelProject?: string;
}

const GATEWAY_HOST = "ai-gateway.vercel.sh";
const DEFAULTS: Record<string, { env: string; baseUrl: string }> = {
  anthropic: {
    env: "ANTHROPIC_API_KEY",
    baseUrl: "https://api.anthropic.com",
  },
  openai: {
    env: "OPENAI_API_KEY",
    baseUrl: "https://api.openai.com/v1",
  },
  xai: {
    env: "XAI_API_KEY",
    baseUrl: "https://api.x.ai/v1",
  },
};

function checkedUrl(value: string, label: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${label} must be a valid URL`);
  }
  if (url.protocol !== "https:") throw new Error(`${label} must use https`);
  if (url.username || url.password) throw new Error(`${label} must not contain credentials`);
  return url;
}

export function isGrokAgent(agentType: string): boolean {
  return agentType === "grok" || agentType === "grok-build";
}

export function modelRouteCompatibilityError(
  route: ModelRoute,
  agentType: string,
): string | undefined {
  if (isGrokAgent(agentType)) return undefined;
  if (route.mode === "custom" && agentType !== "pi") {
    return `Custom model routes require --agent pi (received ${agentType})`;
  }
  if (route.mode === "direct" && route.provider === "anthropic" && agentType === "codex") {
    return "Direct Anthropic credentials are not compatible with --agent codex";
  }
  if (route.mode === "direct" && route.provider === "openai" && agentType === "claude-agent-sdk") {
    return "Direct OpenAI credentials are not compatible with --agent claude";
  }
  return undefined;
}

function resolveGrokModelRoute(env: NodeJS.ProcessEnv): ResolvedModelRoute {
  const credentialEnv = "XAI_API_KEY";
  const credential = env[credentialEnv] ?? "";
  return {
    route: {
      mode: "direct",
      provider: "xai",
      apiKeyEnv: credentialEnv,
      baseUrl: "https://api.x.ai/v1",
    },
    credentialEnv,
    credential,
    environment: credential ? { XAI_API_KEY: credential } : {},
    broker: {
      host: "api.x.ai",
      placeholderEnv: credentialEnv,
      header: {
        name: "authorization",
        value: credential ? `Bearer ${credential}` : "",
      },
    },
  };
}

function assertCompatible(route: ModelRoute, agentType: string): void {
  const error = modelRouteCompatibilityError(route, agentType);
  if (error) throw new Error(error);
}

export function defaultCredentialHeaderScheme(name: string): CredentialHeaderScheme {
  return name.toLowerCase() === "authorization" ? "bearer" : "raw";
}

function headerValue(scheme: CredentialHeaderScheme, credential: string): string {
  return scheme === "bearer" ? `Bearer ${credential}` : credential;
}

export async function resolveModelRoute(
  route: ModelRoute,
  options: ResolveModelRouteOptions,
): Promise<ResolvedModelRoute> {
  const env = options.env ?? process.env;
  if (isGrokAgent(options.agentType)) {
    return resolveGrokModelRoute(env);
  }
  assertCompatible(route, options.agentType);

  if (route.mode === "local") {
    // Local subscriptions delegate auth to the machine-wide claude/codex/pi
    // login. There is no env var to read and no header to broker, so this
    // route can never be resolved — callers must short-circuit before here.
    throw new Error(
      "Local-subscription model routes rely on machine-wide agent logins and have no brokered credential",
    );
  }

  if (route.mode === "gateway") {
    if (route.provider !== "vercel") {
      throw new Error(`Gateway mode only supports provider "vercel"`);
    }
    const credentialEnv = "AI_GATEWAY_API_KEY";
    let credential = env[credentialEnv];
    if (!credential && env.VERCEL_OIDC_TOKEN) {
      credential = await (options.getOidcToken ?? getVercelOidcToken)({
        expirationBufferMs: 60 * 60 * 1000,
        team: options.vercelTeam,
        project: options.vercelProject,
      });
    }
    if (!credential) {
      throw new Error(
        "Selected Vercel AI Gateway route has no credential; set AI_GATEWAY_API_KEY or refresh workspace OIDC",
      );
    }
    const codex = options.agentType === "codex";
    const pi = options.agentType === "pi";
    const environment: Record<string, string> = {
      AI_GATEWAY_API_KEY: credential,
      ...(codex
        ? { OPENAI_API_KEY: credential, OPENAI_BASE_URL: "https://ai-gateway.vercel.sh/v1" }
        : pi
          ? {}
          : {
              ANTHROPIC_AUTH_TOKEN: credential,
              ANTHROPIC_BASE_URL: "https://ai-gateway.vercel.sh",
            }),
    };
    return {
      route,
      credentialEnv,
      credential,
      environment,
      broker: {
        host: GATEWAY_HOST,
        placeholderEnv: credentialEnv,
        header: { name: "authorization", value: `Bearer ${credential}` },
      },
    };
  }

  if (route.mode === "direct") {
    const defaults = DEFAULTS[route.provider];
    if (!defaults) throw new Error(`Unsupported direct model provider: ${route.provider}`);
    const credentialEnv = route.apiKeyEnv ?? defaults.env;
    const credential = env[credentialEnv];
    if (!credential) throw new Error(`Selected ${route.provider} route requires ${credentialEnv}`);
    const baseUrl = route.baseUrl ?? defaults.baseUrl;
    const url = checkedUrl(baseUrl, "AI base URL");
    const isAnthropic = route.provider === "anthropic";
    return {
      route: { ...route, apiKeyEnv: credentialEnv, baseUrl },
      credentialEnv,
      credential,
      environment: isAnthropic
        ? { ANTHROPIC_API_KEY: credential, ANTHROPIC_BASE_URL: baseUrl }
        : { OPENAI_API_KEY: credential, OPENAI_BASE_URL: baseUrl },
      broker: {
        host: url.hostname,
        placeholderEnv: credentialEnv,
        header: isAnthropic
          ? { name: "x-api-key", value: credential }
          : { name: "authorization", value: `Bearer ${credential}` },
      },
    };
  }

  const credentialEnv = route.apiKeyEnv;
  if (!credentialEnv || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(credentialEnv)) {
    throw new Error("Custom model routes require a valid apiKeyEnv");
  }
  if (!route.baseUrl) throw new Error("Custom model routes require an HTTPS baseUrl");
  const credentialHeader =
    route.credentialHeader ??
    (route.authHeader
      ? {
          name: route.authHeader,
          scheme: route.authScheme ?? defaultCredentialHeaderScheme(route.authHeader),
        }
      : undefined);
  if (!credentialHeader?.name || !/^[A-Za-z0-9-]+$/.test(credentialHeader.name)) {
    throw new Error("Custom model routes require a valid credentialHeader name");
  }
  const url = checkedUrl(route.baseUrl, "Custom AI base URL");
  const credential = env[credentialEnv];
  if (!credential) throw new Error(`Selected custom route requires ${credentialEnv}`);
  return {
    route,
    credentialEnv,
    credential,
    environment: {
      [credentialEnv]: credential,
      DEEPSEC_PI_AI_BASE_URL: route.baseUrl,
    },
    broker: {
      host: url.hostname,
      placeholderEnv: credentialEnv,
      header: {
        name: credentialHeader.name.toLowerCase(),
        value: headerValue(credentialHeader.scheme, credential),
      },
    },
  };
}

export function applyResolvedModelRoute(
  resolved: ResolvedModelRoute,
  env: NodeJS.ProcessEnv = process.env,
): void {
  // Claude's direct API-key mode and Gateway bearer-token mode are mutually
  // exclusive. Remove the Gateway value minted by legacy startup defaults so
  // Claude Code cannot prefer it over an explicitly selected direct route.
  if (resolved.route.mode === "direct" && resolved.route.provider === "anthropic") {
    delete env.ANTHROPIC_AUTH_TOKEN;
  }
  for (const [name, value] of Object.entries(resolved.environment)) {
    // Inside a Sandbox, this URL is deliberately pinned to the in-VM request
    // proxy. ANTHROPIC_UPSTREAM_BASE_URL records the provider endpoint that
    // the proxy forwards to; route rehydration must not bypass the proxy.
    if (name === "ANTHROPIC_BASE_URL" && env.ANTHROPIC_UPSTREAM_BASE_URL) continue;
    env[name] = value;
  }
}

export type ModelRouteVerifier = (route: ResolvedModelRoute) => Promise<void>;

function modelsEndpoint(route: ResolvedModelRoute): URL {
  if (route.route.mode === "gateway") return new URL("https://ai-gateway.vercel.sh/v1/models");
  if (route.route.provider === "anthropic")
    return new URL("/v1/models?limit=1", route.route.baseUrl);
  const base = new URL(route.route.baseUrl!);
  base.pathname = `${base.pathname.replace(/\/$/, "")}/models`;
  base.search = "";
  return base;
}

/** Cheap authenticated capability request used by production onboarding. */
export async function verifyModelRouteWithFetch(
  route: ResolvedModelRoute,
  fetchImpl: typeof fetch = fetch,
): Promise<void> {
  if (route.route.provider === "xai" && !route.credential) return;

  const endpoint = modelsEndpoint(route);
  const headers: Record<string, string> = {
    [route.broker.header.name]: route.broker.header.value,
  };
  if (route.route.provider === "anthropic") headers["anthropic-version"] = "2023-06-01";
  let response: Response;
  try {
    response = await fetchImpl(endpoint, {
      method: "GET",
      headers,
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
    });
  } catch (error: any) {
    throw new Error(`Model route verification failed: ${error?.message ?? error}`);
  }
  if (!response.ok) {
    throw new Error(`Model route verification failed with HTTP ${response.status}`);
  }
}

/** Verification is injected so unit tests and provider adapters remain hermetic. */
export async function verifyModelRoute(
  route: ResolvedModelRoute,
  verifier: ModelRouteVerifier,
): Promise<void> {
  await verifier(route);
}

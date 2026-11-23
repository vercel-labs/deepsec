import { getConfig } from "@deepsec/core";
import { type CodexAuthDecision, resolveCodexAuth } from "@deepsec/processor";
import {
  defaultCredentialHeaderScheme,
  type ModelAuthMode,
  type ModelRoute,
  parseCredentialHeader,
} from "./auth/model-route.js";

const THINKING_LEVELS = ["minimal", "low", "medium", "high", "xhigh"] as const;
const CYBER_ACCESS_PROGRAMS = ["standard", "daybreak_blue", "daybreak_red"] as const;

export interface AgentRuntimeOpts {
  agentType: string;
  model?: string;
  maxTurns?: number;
  thinkingLevel?: string;
  aiProvider?: string;
  aiBaseUrl?: string;
  aiApiKeyEnv?: string;
  /** `--ai-credential-header <name[:scheme]>`; custom route auth header for Pi. */
  aiCredentialHeader?: string;
  aiHeader?: string[];
  cyberAccessProgram?: string;
  /** One-run credential route override (`process` / `revalidate --model-auth`). */
  modelAuth?: ModelAuthMode;
  modelRoute?: ModelRoute;
}

export function collectRepeatable(value: string, previous: string[] = []): string[] {
  return [...previous, value];
}

function parseAiHeaders(values: string[] | undefined): Record<string, string> | undefined {
  if (!values || values.length === 0) return undefined;
  const headers: Record<string, string> = {};
  for (const raw of values) {
    const idx = raw.indexOf("=");
    if (idx <= 0) {
      throw new Error(`--ai-header must be NAME=VALUE, got "${raw}"`);
    }
    const name = raw.slice(0, idx).trim();
    const value = raw.slice(idx + 1).trim();
    if (!name) throw new Error(`--ai-header must include a header name, got "${raw}"`);
    headers[name] = value;
  }
  return Object.keys(headers).length > 0 ? headers : undefined;
}

function providerFromModel(model: string | undefined): string | undefined {
  if (!model) return undefined;
  const slash = model.indexOf("/");
  if (slash <= 0) return undefined;
  return model.slice(0, slash);
}

export function buildAgentConfig(opts: AgentRuntimeOpts): Record<string, unknown> {
  const aiHeaders = parseAiHeaders(opts.aiHeader);
  const customRoute = opts.modelRoute?.mode === "custom" ? opts.modelRoute : undefined;
  const aiBaseUrl = opts.aiBaseUrl ?? customRoute?.baseUrl;
  const aiApiKeyEnv = opts.aiApiKeyEnv ?? customRoute?.apiKeyEnv;
  const hasProviderOverride = Boolean(aiBaseUrl || aiApiKeyEnv || aiHeaders);
  const effectiveProvider =
    opts.aiProvider ?? customRoute?.provider ?? providerFromModel(opts.model);
  if (hasProviderOverride && !effectiveProvider) {
    throw new Error(
      `Pi provider override flags require --ai-provider or a provider/model --model value.`,
    );
  }
  const config: Record<string, unknown> = {
    model: opts.model,
    ...(opts.maxTurns ? { maxTurns: opts.maxTurns } : {}),
  };
  const thinkingLevel = opts.thinkingLevel ?? getConfig()?.defaultThinkingLevel;
  if (thinkingLevel) {
    if (!(THINKING_LEVELS as readonly string[]).includes(thinkingLevel)) {
      throw new Error(
        `--thinking-level must be one of ${THINKING_LEVELS.join(", ")}, got "${thinkingLevel}"`,
      );
    }
    // Same dial, different name per harness: pi and claude read
    // thinkingLevel, codex reads reasoningEffort.
    config.thinkingLevel = thinkingLevel;
    config.reasoningEffort = thinkingLevel;
  }
  if (opts.aiProvider || hasProviderOverride) config.aiProvider = effectiveProvider;
  if (aiBaseUrl) config.aiBaseUrl = aiBaseUrl;
  if (aiApiKeyEnv) config.aiApiKeyEnv = aiApiKeyEnv;
  // An explicit per-run flag wins over a rehydrated route, matching the
  // precedence of the other Pi provider overrides above.
  const credentialHeader = opts.aiCredentialHeader
    ? parseCredentialHeader(opts.aiCredentialHeader)
    : (customRoute?.credentialHeader ??
      (customRoute?.authHeader
        ? {
            name: customRoute.authHeader,
            scheme: customRoute.authScheme ?? defaultCredentialHeaderScheme(customRoute.authHeader),
          }
        : undefined));
  if (credentialHeader) {
    config.aiCredentialHeader = credentialHeader;
  }
  if (aiHeaders) config.aiHeaders = aiHeaders;
  // The saved route mode travels with the run so backends can keep a
  // local-subscription choice ahead of ambient provider API keys. Callers
  // skip route resolution when --ai-* selects an explicit provider route, so
  // those runs must not inherit the saved mode. Resolve it before the Cyber
  // Access Program gate so both decisions use the same predicate.
  const savedModelAuth = hasProviderOverride ? undefined : getConfig()?.ai?.mode;
  const modelAuth = opts.modelRoute?.mode ?? savedModelAuth;
  const cyberAccessProgram = resolveCyberAccessProgram(opts, modelAuth);
  if (cyberAccessProgram) config.cyberAccessProgram = cyberAccessProgram;
  if (modelAuth) config.modelAuth = modelAuth;
  return config;
}

/**
 * Cyber Access Programs are a Codex-subscription feature: the gateway's
 * custom provider cannot carry them. This uses the same predicate as the
 * Codex backend ({@link resolveCodexAuth}) so a saved local route still
 * counts as subscription auth when ambient API keys are exported for other
 * tools, instead of being vetoed by them.
 */
function resolveCyberAccessProgram(
  opts: AgentRuntimeOpts,
  modelAuth: string | undefined,
): string | undefined {
  if (opts.agentType !== "codex") {
    if (opts.cyberAccessProgram) throw new Error("--cyber-access-program requires --agent codex");
    return undefined;
  }
  const program = opts.cyberAccessProgram ?? getConfig()?.codex?.cyberAccessProgram;
  if (!program) return undefined;
  if (!(CYBER_ACCESS_PROGRAMS as readonly string[]).includes(program)) {
    throw new Error(
      `--cyber-access-program must be one of ${CYBER_ACCESS_PROGRAMS.join(", ")}, got "${program}"`,
    );
  }
  const auth = resolveCodexAuth({ modelAuth });
  if (auth.mode === "subscription") return program;
  if (opts.cyberAccessProgram) throw new Error(cyberAccessProgramError(auth));
  console.warn(cyberAccessProgramWarning(auth));
  return undefined;
}

/** Accurate CLI error for a program request the effective route cannot honor. */
function cyberAccessProgramError(auth: CodexAuthDecision): string {
  if (auth.localRoute) {
    return (
      "--cyber-access-program only works with Codex subscription auth. " +
      "The saved local-subscription route requires a Codex login, but no Codex login was found " +
      "(expected auth.json in CODEX_HOME or ~/.codex). Run `codex login` and retry."
    );
  }
  if (auth.hasGatewayApiKey) {
    return (
      "--cyber-access-program only works with Codex subscription auth. " +
      "OPENAI_API_KEY or ANTHROPIC_AUTH_TOKEN routes this run through the AI Gateway, " +
      "whose custom provider cannot carry the program. Unset those variables " +
      "(or select the local-subscription route during setup) and use `codex login` instead."
    );
  }
  return (
    "--cyber-access-program only works with Codex subscription auth. " +
    "Run `codex login`, or select the local-subscription route during setup."
  );
}

/** Matching warning when a config-file program is silently unusable. */
function cyberAccessProgramWarning(auth: CodexAuthDecision): string {
  const reason = auth.localRoute
    ? "the saved local-subscription route has no Codex login, so the run requires `codex login`"
    : auth.hasGatewayApiKey
      ? "this run uses gateway auth because OPENAI_API_KEY or ANTHROPIC_AUTH_TOKEN is set"
      : "this run doesn't use Codex subscription auth";
  return `Ignoring codex.cyberAccessProgram from deepsec.config.ts: ${reason}.`;
}

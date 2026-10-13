import { getConfig } from "@deepsec/core";
import { defaultCredentialHeaderScheme, type ModelRoute } from "./auth/model-route.js";

const THINKING_LEVELS = ["minimal", "low", "medium", "high", "xhigh"] as const;

interface AgentRuntimeOpts {
  model?: string;
  maxTurns?: number;
  thinkingLevel?: string;
  aiProvider?: string;
  aiBaseUrl?: string;
  aiApiKeyEnv?: string;
  aiHeader?: string[];
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
  const credentialHeader =
    customRoute?.credentialHeader ??
    (customRoute?.authHeader
      ? {
          name: customRoute.authHeader,
          scheme: customRoute.authScheme ?? defaultCredentialHeaderScheme(customRoute.authHeader),
        }
      : undefined);
  if (credentialHeader) {
    config.aiCredentialHeader = credentialHeader;
  }
  if (aiHeaders) config.aiHeaders = aiHeaders;
  return config;
}

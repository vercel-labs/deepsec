const THINKING_LEVELS = ["minimal", "low", "medium", "high", "xhigh"] as const;
const FIREWORKS_KIMI_K3_MODEL = "fireworks/accounts/fireworks/models/kimi-k3";
const FIREWORKS_PROVIDER = "fireworks";
const FIREWORKS_BASE_URL = "https://api.fireworks.ai/inference/v1";
const FIREWORKS_API_KEY_ENV = "FIREWORKS_API_KEY";

interface AgentRuntimeOpts {
  model?: string;
  maxTurns?: number;
  thinkingLevel?: string;
  aiProvider?: string;
  aiBaseUrl?: string;
  aiApiKeyEnv?: string;
  aiHeader?: string[];
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
  const useFireworksKimiK3Preset =
    opts.model === FIREWORKS_KIMI_K3_MODEL &&
    (!opts.aiProvider || opts.aiProvider === FIREWORKS_PROVIDER);
  const aiBaseUrl = opts.aiBaseUrl ?? (useFireworksKimiK3Preset ? FIREWORKS_BASE_URL : undefined);
  const aiBaseUrlFromPreset = !opts.aiBaseUrl && useFireworksKimiK3Preset;
  const aiApiKeyEnv =
    opts.aiApiKeyEnv ?? (useFireworksKimiK3Preset ? FIREWORKS_API_KEY_ENV : undefined);
  const hasProviderOverride = Boolean(aiBaseUrl || aiApiKeyEnv || aiHeaders);
  const effectiveProvider =
    opts.aiProvider ??
    (useFireworksKimiK3Preset ? FIREWORKS_PROVIDER : providerFromModel(opts.model));
  if (hasProviderOverride && !effectiveProvider) {
    throw new Error(
      `Pi provider override flags require --ai-provider or a provider/model --model value.`,
    );
  }
  const config: Record<string, unknown> = {
    model: opts.model,
    ...(opts.maxTurns ? { maxTurns: opts.maxTurns } : {}),
  };
  if (opts.thinkingLevel) {
    if (!(THINKING_LEVELS as readonly string[]).includes(opts.thinkingLevel)) {
      throw new Error(
        `--thinking-level must be one of ${THINKING_LEVELS.join(", ")}, got "${opts.thinkingLevel}"`,
      );
    }
    // Same dial, different name per harness: pi and claude read
    // thinkingLevel, codex reads reasoningEffort.
    config.thinkingLevel = opts.thinkingLevel;
    config.reasoningEffort = opts.thinkingLevel;
  }
  if (opts.aiProvider || hasProviderOverride) config.aiProvider = effectiveProvider;
  if (aiBaseUrl) config.aiBaseUrl = aiBaseUrl;
  if (aiBaseUrlFromPreset) config.aiBaseUrlFromPreset = true;
  if (aiApiKeyEnv) config.aiApiKeyEnv = aiApiKeyEnv;
  if (aiHeaders) config.aiHeaders = aiHeaders;
  return config;
}

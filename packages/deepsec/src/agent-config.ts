import { ATLAS_API_KEY_ENV, ATLAS_BASE_URL, ATLAS_PROVIDER } from "./atlas-provider.js";

const THINKING_LEVELS = ["minimal", "low", "medium", "high", "xhigh"] as const;

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
  const hasProviderOverride = Boolean(opts.aiBaseUrl || opts.aiApiKeyEnv || aiHeaders);
  const effectiveProvider = opts.aiProvider ?? providerFromModel(opts.model);
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
  if (effectiveProvider === ATLAS_PROVIDER) {
    config.aiProvider = ATLAS_PROVIDER;
    config.aiBaseUrl = opts.aiBaseUrl ?? ATLAS_BASE_URL;
    config.aiApiKeyEnv = opts.aiApiKeyEnv ?? ATLAS_API_KEY_ENV;
  } else {
    if (opts.aiBaseUrl) config.aiBaseUrl = opts.aiBaseUrl;
    if (opts.aiApiKeyEnv) config.aiApiKeyEnv = opts.aiApiKeyEnv;
  }
  if (aiHeaders) config.aiHeaders = aiHeaders;
  return config;
}

import { defaultCredentialHeaderScheme, type ModelRoute } from "../auth/model-route.js";

export interface ModelRouteCliOptions {
  modelAuth?: "gateway" | "direct" | "custom" | "local";
  aiProvider?: string;
  aiApiKeyEnv?: string;
  aiBaseUrl?: string;
  aiCredentialHeader?: string;
  agent?: string;
}

export function modelRouteFromCli(options: ModelRouteCliOptions): ModelRoute {
  const mode = options.modelAuth ?? "gateway";
  if (mode !== "gateway" && mode !== "direct" && mode !== "custom" && mode !== "local") {
    throw new Error("--model-auth must be gateway, direct, custom, or local");
  }
  if (mode === "gateway") return { mode, provider: "vercel" };
  if (mode === "local") return { mode, provider: "local" };
  const provider =
    options.aiProvider ??
    (options.agent === "claude" || options.agent === "claude-agent-sdk"
      ? "anthropic"
      : options.agent === "codex"
        ? "openai"
        : options.agent === "grok" || options.agent === "grok-build"
          ? "xai"
          : undefined);
  if (!provider) throw new Error(`--model-auth ${mode} requires --ai-provider`);
  if (mode === "direct") {
    return {
      mode,
      provider,
      apiKeyEnv: options.aiApiKeyEnv,
      baseUrl: options.aiBaseUrl,
    };
  }
  if (!options.aiApiKeyEnv || !options.aiBaseUrl || !options.aiCredentialHeader) {
    throw new Error(
      "--model-auth custom requires --ai-api-key-env, --ai-base-url, and --ai-credential-header",
    );
  }
  const [name, explicitScheme] = options.aiCredentialHeader.split(":");
  const scheme = explicitScheme ?? defaultCredentialHeaderScheme(name);
  if (scheme !== "bearer" && scheme !== "raw") {
    throw new Error("--ai-credential-header scheme must be bearer or raw");
  }
  return {
    mode,
    provider,
    apiKeyEnv: options.aiApiKeyEnv,
    baseUrl: options.aiBaseUrl,
    credentialHeader: { name, scheme },
  };
}

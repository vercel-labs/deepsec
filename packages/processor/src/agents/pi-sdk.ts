import fs from "node:fs";
import path from "node:path";
import type { RefusalReport } from "@deepsec/core";
import {
  type AgentSession,
  type AgentSessionEvent,
  AuthStorage,
  createAgentSession,
  createFindToolDefinition,
  createGrepToolDefinition,
  createLsToolDefinition,
  createReadToolDefinition,
  DefaultResourceLoader,
  getAgentDir,
  ModelRegistry,
  SessionManager,
  SettingsManager,
  type ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import {
  backoff,
  buildInvestigateJsonRepairPrompt,
  buildInvestigatePrompt,
  buildRevalidateJsonRepairPrompt,
  buildRevalidatePrompt,
  classifyQuotaError,
  formatJsonRepairFailureDebugText,
  isTransientError,
  isUsingAiGateway,
  jsonRepairFailureError,
  MAX_ATTEMPTS,
  parseInvestigateResults,
  parseRefusalReport,
  parseRevalidateVerdicts,
  QuotaExhaustedError,
  REFUSAL_FOLLOWUP_PROMPT,
  writeParseFailureDebug,
} from "./shared.js";
import type {
  AgentPlugin,
  AgentProgress,
  BatchMeta,
  InvestigateOutput,
  InvestigateParams,
  InvestigateResult,
  RevalidateOutput,
  RevalidateParams,
  RevalidateVerdict,
} from "./types.js";

const DEFAULT_MODEL = "zai/glm-5.2";
const DEFAULT_THINKING_LEVEL = "xhigh";
const DEFAULT_TOOLS = ["read", "grep", "find", "ls"];
const GATEWAY_PROVIDER = "vercel-ai-gateway";
const GATEWAY_BASE_URL = "https://ai-gateway.vercel.sh/v1";
const TOOL_ERROR_DETAIL_LIMIT = 500;

const DEEPSEC_SYSTEM_NOTE =
  "You are running inside the Pi harness for deepsec. Use source inspection only. Do not run the target application, send network requests, or attempt exploitation. Return only the requested JSON object.";
const FIND_SKIP_DIRS = new Set([".git", "node_modules"]);

interface PiAgentConfig {
  model?: string;
  maxTurns?: number;
  aiProvider?: string;
  aiBaseUrl?: string;
  aiApiKeyEnv?: string;
  aiHeaders?: Record<string, string>;
  thinkingLevel?: string;
}

type PiModel = ReturnType<ModelRegistry["getAll"]>[number];
type PiProviderConfig = Parameters<ModelRegistry["registerProvider"]>[1];
type PiProviderModelConfig = NonNullable<PiProviderConfig["models"]>[number];

interface PiSessionSetup {
  session: AgentSession;
  modelLabel: string;
}

interface PiPromptResult {
  resultText: string;
  meta: Partial<BatchMeta>;
  turnCount: number;
  toolUseCount: number;
}

interface RootGuard {
  rootPath: string;
  rootRealPath: string;
}

function pathIsInside(parent: string, candidate: string): boolean {
  const relative = path.relative(parent, candidate);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function createRootGuard(projectRoot: string): RootGuard {
  return {
    rootPath: path.resolve(projectRoot),
    rootRealPath: fs.realpathSync.native(projectRoot),
  };
}

function assertLexicallyInsideProjectRoot(guard: RootGuard, absolutePath: string): string {
  const resolved = path.resolve(absolutePath);
  if (!pathIsInside(guard.rootPath, resolved)) {
    throw new Error(`Path escapes project root: ${absolutePath}`);
  }
  return resolved;
}

function assertInsideProjectRoot(guard: RootGuard, absolutePath: string): string {
  const resolved = assertLexicallyInsideProjectRoot(guard, absolutePath);
  const realPath = fs.realpathSync.native(resolved);
  if (!pathIsInside(guard.rootRealPath, realPath)) {
    throw new Error(`Path escapes project root: ${absolutePath}`);
  }
  return resolved;
}

function assertInsideProjectRootAllowMissing(guard: RootGuard, absolutePath: string): string {
  const resolved = assertLexicallyInsideProjectRoot(guard, absolutePath);
  try {
    const realPath = fs.realpathSync.native(resolved);
    if (!pathIsInside(guard.rootRealPath, realPath)) {
      throw new Error(`Path escapes project root: ${absolutePath}`);
    }
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code !== "ENOENT" && code !== "ENOTDIR") throw err;
  }
  return resolved;
}

function toPosixPath(value: string): string {
  return value.split(path.sep).join("/");
}

function escapeRegexChar(value: string): string {
  return value.replace(/[|\\{}()[\]^$+?.]/g, "\\$&");
}

function globToRegExp(pattern: string): RegExp {
  const normalized = toPosixPath(pattern)
    .replace(/^\.?\//, "")
    .replace(/^\/+/, "");
  let source = "^";
  for (let i = 0; i < normalized.length; i++) {
    const char = normalized[i];
    if (char === "*") {
      if (normalized[i + 1] === "*") {
        if (normalized[i + 2] === "/") {
          source += "(?:.*\\/)?";
          i += 2;
        } else {
          source += ".*";
          i += 1;
        }
      } else {
        source += "[^/]*";
      }
    } else if (char === "?") {
      source += "[^/]";
    } else if (char === "/") {
      source += "\\/";
    } else {
      source += escapeRegexChar(char);
    }
  }
  source += "$";
  return new RegExp(source);
}

function matchesFindPattern(relativePath: string, pattern: string): boolean {
  const normalized = toPosixPath(relativePath);
  const target = pattern.includes("/") ? normalized : path.posix.basename(normalized);
  return globToRegExp(pattern).test(target);
}

async function guardedGlob(
  guard: RootGuard,
  pattern: string,
  searchRoot: string,
  limit: number,
): Promise<string[]> {
  const guardedRoot = assertInsideProjectRoot(guard, searchRoot);
  const results: string[] = [];

  async function walk(dir: string): Promise<void> {
    if (results.length >= limit) return;
    const guardedDir = assertInsideProjectRoot(guard, dir);
    const entries = await fs.promises.readdir(guardedDir, { withFileTypes: true });
    entries.sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()));

    for (const entry of entries) {
      if (results.length >= limit) return;
      if (FIND_SKIP_DIRS.has(entry.name)) continue;
      const fullPath = path.join(guardedDir, entry.name);
      if (entry.isDirectory()) {
        await walk(fullPath);
        continue;
      }
      if (!entry.isFile() && !entry.isSymbolicLink()) continue;
      try {
        assertInsideProjectRoot(guard, fullPath);
      } catch {
        continue;
      }
      const relativePath = path.relative(guardedRoot, fullPath);
      if (matchesFindPattern(relativePath, pattern)) {
        results.push(fullPath);
      }
    }
  }

  await walk(guardedRoot);
  return results;
}

export function createPiReadOnlyToolDefinitions(projectRoot: string): ToolDefinition<any, any>[] {
  const guard = createRootGuard(projectRoot);
  return [
    createReadToolDefinition(projectRoot, {
      operations: {
        readFile: (absolutePath) =>
          fs.promises.readFile(assertInsideProjectRoot(guard, absolutePath)),
        access: (absolutePath) =>
          fs.promises.access(assertInsideProjectRoot(guard, absolutePath), fs.constants.R_OK),
      },
    }),
    createGrepToolDefinition(projectRoot, {
      operations: {
        isDirectory: async (absolutePath) =>
          (await fs.promises.stat(assertInsideProjectRoot(guard, absolutePath))).isDirectory(),
        readFile: (absolutePath) =>
          fs.promises.readFile(assertInsideProjectRoot(guard, absolutePath), "utf8"),
      },
    }),
    createFindToolDefinition(projectRoot, {
      operations: {
        exists: (absolutePath) =>
          fs.existsSync(assertInsideProjectRootAllowMissing(guard, absolutePath)),
        glob: (pattern, cwd, options) => guardedGlob(guard, pattern, cwd, options.limit),
      },
    }),
    createLsToolDefinition(projectRoot, {
      operations: {
        exists: (absolutePath) =>
          fs.existsSync(assertInsideProjectRootAllowMissing(guard, absolutePath)),
        stat: (absolutePath) => fs.promises.stat(assertInsideProjectRoot(guard, absolutePath)),
        readdir: (absolutePath) =>
          fs.promises.readdir(assertInsideProjectRoot(guard, absolutePath)),
      },
    }),
  ] as ToolDefinition<any, any>[];
}

function readConfig(config: Record<string, unknown>): PiAgentConfig {
  return {
    model: typeof config.model === "string" ? config.model : undefined,
    maxTurns: typeof config.maxTurns === "number" ? config.maxTurns : undefined,
    aiProvider: typeof config.aiProvider === "string" ? config.aiProvider : undefined,
    aiBaseUrl: typeof config.aiBaseUrl === "string" ? config.aiBaseUrl : undefined,
    aiApiKeyEnv: typeof config.aiApiKeyEnv === "string" ? config.aiApiKeyEnv : undefined,
    aiHeaders:
      config.aiHeaders && typeof config.aiHeaders === "object" && !Array.isArray(config.aiHeaders)
        ? (config.aiHeaders as Record<string, string>)
        : undefined,
    thinkingLevel: typeof config.thinkingLevel === "string" ? config.thinkingLevel : undefined,
  };
}

function modelProviderFromName(modelName: string | undefined): string | undefined {
  if (!modelName) return undefined;
  const slash = modelName.indexOf("/");
  if (slash <= 0) return undefined;
  return modelName.slice(0, slash);
}

function stripGatewayProviderPrefix(modelName: string): string {
  const prefix = `${GATEWAY_PROVIDER}/`;
  return modelName.startsWith(prefix) ? modelName.slice(prefix.length) : modelName;
}

function isGatewayModelRequest(requested: string, cfg: PiAgentConfig): boolean {
  return Boolean(
    isUsingAiGateway() && !cfg.aiBaseUrl && !cfg.aiProvider && requested.includes("/"),
  );
}

function getGatewayCredential(): string | undefined {
  return (
    process.env.AI_GATEWAY_API_KEY ??
    process.env.VERCEL_OIDC_TOKEN ??
    process.env.OPENAI_API_KEY ??
    process.env.ANTHROPIC_AUTH_TOKEN ??
    process.env.ANTHROPIC_API_KEY
  );
}

function configureRuntimeAuth(authStorage: AuthStorage, cfg: PiAgentConfig): void {
  const gatewayKey = getGatewayCredential();
  if (gatewayKey) authStorage.setRuntimeApiKey(GATEWAY_PROVIDER, gatewayKey);

  const anthropicKey = process.env.ANTHROPIC_API_KEY ?? process.env.ANTHROPIC_AUTH_TOKEN;
  if (anthropicKey) authStorage.setRuntimeApiKey("anthropic", anthropicKey);

  const openaiKey = process.env.OPENAI_API_KEY;
  if (openaiKey) authStorage.setRuntimeApiKey("openai", openaiKey);

  const customProvider = cfg.aiProvider ?? modelProviderFromName(cfg.model);
  if (customProvider && cfg.aiApiKeyEnv) {
    const key = process.env[cfg.aiApiKeyEnv];
    if (key) authStorage.setRuntimeApiKey(customProvider, key);
  }
}

function configureProviderOverrides(registry: ModelRegistry, cfg: PiAgentConfig): void {
  if (process.env.ANTHROPIC_BASE_URL) {
    registry.registerProvider("anthropic", { baseUrl: process.env.ANTHROPIC_BASE_URL });
  }
  if (process.env.OPENAI_BASE_URL) {
    registry.registerProvider("openai", { baseUrl: process.env.OPENAI_BASE_URL });
  }

  const provider = cfg.aiProvider ?? modelProviderFromName(cfg.model);
  if (!provider) return;
  const override: Parameters<ModelRegistry["registerProvider"]>[1] = {};
  if (cfg.aiBaseUrl) override.baseUrl = cfg.aiBaseUrl;
  if (cfg.aiHeaders && Object.keys(cfg.aiHeaders).length > 0) override.headers = cfg.aiHeaders;
  if (Object.keys(override).length > 0) {
    registry.registerProvider(provider, override);
  }
}

function createGatewayPassThroughModel(modelId: string): PiProviderModelConfig {
  return {
    id: modelId,
    name: modelId,
    api: "openai-completions",
    reasoning: true,
    input: ["text", "image"],
    cost: {
      input: 0,
      output: 0,
      cacheRead: 0,
      cacheWrite: 0,
    },
    contextWindow: 128_000,
    maxTokens: 32_000,
  };
}

function piModelToProviderModelConfig(model: PiModel): PiProviderModelConfig {
  return {
    id: model.id,
    name: model.name,
    api: model.api,
    reasoning: model.reasoning,
    thinkingLevelMap: model.thinkingLevelMap,
    input: model.input,
    cost: model.cost,
    contextWindow: model.contextWindow,
    maxTokens: model.maxTokens,
    compat: model.compat,
  };
}

function dedupeProviderModels(models: PiProviderModelConfig[]): PiProviderModelConfig[] {
  const byId = new Map<string, PiProviderModelConfig>();
  for (const model of models) byId.set(model.id, model);
  return Array.from(byId.values());
}

function registerGatewayModelIfNeeded(
  registry: ModelRegistry,
  requested: string,
  cfg: PiAgentConfig,
): void {
  if (!isGatewayModelRequest(requested, cfg)) return;
  const gatewayModelId = stripGatewayProviderPrefix(requested);
  if (registry.find(GATEWAY_PROVIDER, gatewayModelId)) return;

  const existingGatewayModels = registry
    .getAll()
    .filter((model) => model.provider === GATEWAY_PROVIDER)
    .map(piModelToProviderModelConfig);
  const models = dedupeProviderModels([
    ...existingGatewayModels,
    createGatewayPassThroughModel(gatewayModelId),
  ]);

  registry.registerProvider(GATEWAY_PROVIDER, {
    baseUrl: GATEWAY_BASE_URL,
    apiKey: getGatewayCredential() ?? "$AI_GATEWAY_API_KEY",
    api: "openai-completions",
    models,
  });
}

function createAuthStorage(): AuthStorage {
  const authPath = path.join(getAgentDir(), "auth.json");
  return fs.existsSync(authPath) ? AuthStorage.create(authPath) : AuthStorage.inMemory();
}

function resolvePiModel(registry: ModelRegistry, requested: string, cfg: PiAgentConfig): PiModel {
  const preferGateway = Boolean(isUsingAiGateway() && !cfg.aiBaseUrl && !cfg.aiProvider);
  if (preferGateway) {
    const gatewayModel = registry.find(GATEWAY_PROVIDER, stripGatewayProviderPrefix(requested));
    if (gatewayModel) return gatewayModel;
  }

  const slash = requested.indexOf("/");
  if (slash > 0) {
    const provider = requested.slice(0, slash);
    const modelId = requested.slice(slash + 1);
    const gatewayModel = registry.find(GATEWAY_PROVIDER, requested);
    if (gatewayModel) return gatewayModel;

    const direct = registry.find(provider, modelId);
    if (direct && !preferGateway) return direct;
    if (direct && registry.hasConfiguredAuth(direct)) return direct;
  } else {
    const matches = registry.getAll().filter((m) => m.id === requested);
    const gatewayMatch = matches.find((m) => m.provider === GATEWAY_PROVIDER);
    const availableMatch = matches.find((m) => registry.hasConfiguredAuth(m));
    const firstMatch = preferGateway
      ? (gatewayMatch ?? availableMatch)
      : (availableMatch ?? gatewayMatch);
    if (firstMatch) return firstMatch;
  }

  const examples = registry
    .getAll()
    .slice(0, 8)
    .map((m) => `${m.provider}/${m.id}`)
    .join(", ");
  throw new Error(
    `Pi model not found: ${requested}. Use provider/model, for example ${examples || DEFAULT_MODEL}.`,
  );
}

export async function resolvePiModelWithDynamicGateway(
  registry: ModelRegistry,
  requested: string,
  cfg: PiAgentConfig,
): Promise<PiModel> {
  try {
    return resolvePiModel(registry, requested, cfg);
  } catch (err) {
    registerGatewayModelIfNeeded(registry, requested, cfg);
    try {
      return resolvePiModel(registry, requested, cfg);
    } catch {
      throw err;
    }
  }
}

async function createPiSession(projectRoot: string, cfg: PiAgentConfig): Promise<PiSessionSetup> {
  const authStorage = createAuthStorage();
  configureRuntimeAuth(authStorage, cfg);

  const modelRegistry = ModelRegistry.create(authStorage, path.join(getAgentDir(), "models.json"));
  configureProviderOverrides(modelRegistry, cfg);

  const modelName = cfg.model ?? DEFAULT_MODEL;
  const model = await resolvePiModelWithDynamicGateway(modelRegistry, modelName, cfg);
  const agentDir = getAgentDir();
  const settingsManager = SettingsManager.inMemory({
    defaultThinkingLevel: (cfg.thinkingLevel ?? DEFAULT_THINKING_LEVEL) as never,
    compaction: { enabled: false },
    retry: { enabled: true },
    terminal: { showTerminalProgress: false },
    images: { blockImages: true },
  });
  const resourceLoader = new DefaultResourceLoader({
    cwd: projectRoot,
    agentDir,
    settingsManager,
    noExtensions: true,
    noSkills: true,
    noPromptTemplates: true,
    noThemes: true,
    noContextFiles: true,
    appendSystemPrompt: [DEEPSEC_SYSTEM_NOTE],
  });
  await resourceLoader.reload();

  const result = await createAgentSession({
    cwd: projectRoot,
    agentDir,
    authStorage,
    modelRegistry,
    settingsManager,
    resourceLoader,
    sessionManager: SessionManager.inMemory(projectRoot),
    model,
    thinkingLevel: (cfg.thinkingLevel ?? DEFAULT_THINKING_LEVEL) as never,
    tools: DEFAULT_TOOLS,
    customTools: createPiReadOnlyToolDefinitions(projectRoot),
  });

  return {
    session: result.session,
    modelLabel: `${model.provider}/${model.id}`,
  };
}

function shortTarget(input: unknown): string | undefined {
  if (!input || typeof input !== "object") return undefined;
  const record = input as Record<string, unknown>;
  for (const key of ["path", "filePath", "file_path", "pattern", "query", "command"]) {
    const value = record[key];
    if (typeof value === "string" && value.trim()) {
      return value.split("/").slice(-3).join("/");
    }
  }
  return undefined;
}

function compactOneLine(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

function truncateLogDetail(value: string): string {
  const compacted = compactOneLine(value);
  if (compacted.length <= TOOL_ERROR_DETAIL_LIMIT) return compacted;
  return `${compacted.slice(0, TOOL_ERROR_DETAIL_LIMIT)}...`;
}

function textFromToolContent(content: unknown): string | undefined {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return undefined;
  const parts: string[] = [];
  for (const item of content) {
    if (typeof item === "string") {
      parts.push(item);
      continue;
    }
    if (!item || typeof item !== "object") continue;
    const record = item as Record<string, unknown>;
    if (typeof record.text === "string") parts.push(record.text);
  }
  return parts.length > 0 ? parts.join(" ") : undefined;
}

function summarizeToolError(result: unknown): string | undefined {
  if (!result) return undefined;
  if (typeof result === "string") return truncateLogDetail(result);
  if (result instanceof Error) return truncateLogDetail(result.message);
  if (typeof result !== "object") return truncateLogDetail(String(result));

  const record = result as Record<string, unknown>;
  for (const key of ["error", "message", "reason", "stderr", "stdout"]) {
    const value = record[key];
    if (typeof value === "string" && value.trim()) {
      return truncateLogDetail(value);
    }
  }

  const contentText = textFromToolContent(record.content);
  if (contentText) return truncateLogDetail(contentText);

  try {
    return truncateLogDetail(JSON.stringify(result));
  } catch {
    return undefined;
  }
}

function formatToolErrorMessage(
  toolName: string | undefined,
  target: string | undefined,
  result: unknown,
): string {
  const targetStr = target ? `: ${target}` : "";
  const detail = summarizeToolError(result);
  const detailStr = detail ? ` - ${detail}` : "";
  return `Pi tool error: ${toolName ?? "tool"}${targetStr}${detailStr}`;
}

function batchMetaFromSession(session: AgentSession, durationMs: number): Partial<BatchMeta> {
  const stats = session.getSessionStats();
  return {
    durationMs,
    numTurns: stats.assistantMessages,
    costUsd: stats.cost,
    agentSessionId: stats.sessionId,
    usage: {
      inputTokens: stats.tokens.input,
      outputTokens: stats.tokens.output,
      cacheReadInputTokens: stats.tokens.cacheRead,
      cacheCreationInputTokens: stats.tokens.cacheWrite,
    },
  };
}

async function* runPiPrompt(params: {
  session: AgentSession;
  prompt: string;
  label: string;
  maxTurns: number;
  signal?: AbortSignal;
}): AsyncGenerator<AgentProgress, PiPromptResult> {
  const { session, prompt, label, maxTurns, signal } = params;
  const startTime = Date.now();
  const queue: AgentProgress[] = [];
  let notify: (() => void) | undefined;
  let done = false;
  let promptError: unknown;
  let turnCount = 0;
  let toolUseCount = 0;
  let lastAssistantError: string | undefined;
  const toolTargets = new Map<string, string | undefined>();

  const wake = () => {
    const fn = notify;
    notify = undefined;
    fn?.();
  };
  const push = (progress: AgentProgress) => {
    queue.push(progress);
    wake();
  };

  const unsubscribe = session.subscribe((event: AgentSessionEvent) => {
    const e = event as Record<string, any>;
    if (process.env.DEEPSEC_PI_DEBUG === "1" && event.type !== "message_update") {
      try {
        console.error(`[pi-debug] ${JSON.stringify(event).slice(0, 2000)}`);
      } catch {
        console.error(`[pi-debug] ${event.type} (unserializable)`);
      }
    }
    switch (event.type) {
      case "turn_start":
        turnCount++;
        push({
          type: "thinking",
          message: `Pi turn ${turnCount} (${label})`,
        });
        if (turnCount > maxTurns) {
          promptError = new Error(`Pi exceeded max turns (${maxTurns})`);
          void session.abort();
        }
        break;
      case "tool_execution_start": {
        toolUseCount++;
        const target = shortTarget(e.args);
        if (typeof e.toolCallId === "string") toolTargets.set(e.toolCallId, target);
        push({
          type: "tool_use",
          message: `${e.toolName ?? "tool"}${target ? `: ${target}` : ""}`,
          candidateFile: target,
        });
        break;
      }
      case "message_end": {
        // API failures (e.g. gateway 403s) surface as assistant messages with
        // stopReason "error" — session.prompt() resolves normally, so without
        // this the run ends with an empty result and "(none captured)".
        const message = e.message as Record<string, any> | undefined;
        if (message?.role === "assistant" && message.stopReason === "error") {
          lastAssistantError =
            typeof message.errorMessage === "string" && message.errorMessage.trim()
              ? message.errorMessage
              : "Pi model request failed without an error message";
          push({
            type: "error",
            message: `Pi model error: ${truncateLogDetail(lastAssistantError)}`,
          });
        }
        break;
      }
      case "tool_execution_end":
        if (e.isError) {
          const target =
            typeof e.toolCallId === "string" ? toolTargets.get(e.toolCallId) : undefined;
          push({
            type: "error",
            message: formatToolErrorMessage(e.toolName, target, e.result),
          });
        }
        if (typeof e.toolCallId === "string") toolTargets.delete(e.toolCallId);
        break;
      case "auto_retry_start":
        push({
          type: "thinking",
          message: `Pi retry ${e.attempt}/${e.maxAttempts}: ${String(e.errorMessage ?? "").slice(0, 200)}`,
        });
        break;
      case "compaction_start":
        push({ type: "thinking", message: "Pi compacting conversation context" });
        break;
      case "agent_end":
        if (e.willRetry) {
          push({ type: "thinking", message: "Pi will retry this turn" });
        }
        break;
    }
  });

  const abort = () => {
    void session.abort();
    wake();
  };
  if (signal) {
    if (signal.aborted) abort();
    else signal.addEventListener("abort", abort, { once: true });
  }

  const promptPromise = session
    .prompt(prompt, { expandPromptTemplates: false, source: "programmatic" as never })
    .catch((err) => {
      promptError = promptError ?? err;
    })
    .finally(() => {
      done = true;
      wake();
    });

  try {
    while (!done || queue.length > 0) {
      const next = queue.shift();
      if (next) {
        yield next;
        continue;
      }
      await new Promise<void>((resolve) => {
        notify = resolve;
      });
    }
    await promptPromise;
  } finally {
    unsubscribe();
    if (signal) signal.removeEventListener("abort", abort);
  }

  if (promptError) {
    throw promptError;
  }
  const finalText = session.getLastAssistantText() ?? "";
  if (!finalText && lastAssistantError) {
    throw new Error(lastAssistantError);
  }

  const durationMs = Date.now() - startTime;
  return {
    resultText: finalText,
    meta: batchMetaFromSession(session, durationMs),
    turnCount,
    toolUseCount,
  };
}

async function runRefusalFollowUp(
  session: AgentSession | undefined,
  signal?: AbortSignal,
): Promise<RefusalReport | undefined> {
  const raw = await runToollessFollowUp(session, REFUSAL_FOLLOWUP_PROMPT, signal);
  if (raw === undefined) return undefined;
  return parseRefusalReport(raw);
}

async function runToollessFollowUp(
  session: AgentSession | undefined,
  prompt: string,
  signal?: AbortSignal,
): Promise<string | undefined> {
  if (!session) return undefined;
  const previousTools = session.getActiveToolNames();
  const abort = () => void session.abort();
  if (signal) {
    if (signal.aborted) abort();
    else signal.addEventListener("abort", abort, { once: true });
  }
  try {
    session.setActiveToolsByName([]);
    await session.prompt(prompt, {
      expandPromptTemplates: false,
      source: "programmatic" as never,
    });
    return session.getLastAssistantText() ?? "";
  } catch {
    return undefined;
  } finally {
    session.setActiveToolsByName(previousTools);
    if (signal) signal.removeEventListener("abort", abort);
  }
}

export class PiAgentPlugin implements AgentPlugin {
  type = "pi";

  async *investigate(params: InvestigateParams): AsyncGenerator<AgentProgress, InvestigateOutput> {
    const { batch, projectRoot, promptTemplate, projectInfo, config, signal, projectId } = params;
    const cfg = readConfig(config);
    const maxTurns = cfg.maxTurns ?? 150;
    const prompt = buildInvestigatePrompt({ promptTemplate, projectInfo, batch });
    const startTime = Date.now();

    let resultText = "";
    let lastError = "";
    let session: AgentSession | undefined;
    let modelLabel = cfg.model ?? DEFAULT_MODEL;
    let sdkMeta: Partial<BatchMeta> = {};
    let turnCount = 0;
    let toolUseCount = 0;

    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      if (attempt > 1) {
        yield {
          type: "thinking",
          message: `Retrying Pi batch after transient error (attempt ${attempt}/${MAX_ATTEMPTS}): ${lastError.slice(0, 200)}`,
        };
        session?.dispose();
        session = undefined;
        resultText = "";
        lastError = "";
        sdkMeta = {};
        turnCount = 0;
        toolUseCount = 0;
      }

      try {
        const setup = await createPiSession(projectRoot, cfg);
        session = setup.session;
        modelLabel = setup.modelLabel;
        if (attempt === 1) {
          yield {
            type: "started",
            message: `Investigating ${batch.length} file(s) with Pi (${modelLabel})`,
          };
        }
        const run = yield* runPiPrompt({
          session,
          prompt,
          label: "investigate",
          maxTurns,
          signal,
        });
        resultText = run.resultText;
        sdkMeta = run.meta;
        turnCount = run.turnCount;
        toolUseCount = run.toolUseCount;
      } catch (err) {
        lastError = err instanceof Error ? err.message : String(err);
        yield { type: "error", message: `Pi SDK error: ${lastError.slice(0, 300)}` };
      }

      if (resultText) break;
      const quotaSource = classifyQuotaError(lastError);
      if (quotaSource) {
        throw new QuotaExhaustedError(quotaSource, lastError);
      }
      if (attempt >= MAX_ATTEMPTS || !isTransientError(lastError)) break;
      await backoff(attempt);
    }

    if (!resultText) {
      session?.dispose();
      throw new Error(
        `Pi produced no investigation result after ${MAX_ATTEMPTS} attempt(s). ` +
          `Last error: ${lastError || "(none captured)"}.`,
      );
    }

    const durationMs = Date.now() - startTime;
    let results: InvestigateResult[];
    try {
      results = parseInvestigateResults(resultText, batch);
    } catch (err) {
      yield {
        type: "thinking",
        message: "Pi returned non-JSON investigation output; requesting JSON-only repair",
      };
      const repairText = await runToollessFollowUp(
        session,
        buildInvestigateJsonRepairPrompt(batch),
        signal,
      );
      if (repairText === undefined) {
        writeParseFailureDebug({
          projectId,
          phase: "investigate",
          agentType: this.type,
          resultText,
          error: err,
          batch,
        });
        session?.dispose();
        throw err;
      }
      try {
        results = parseInvestigateResults(repairText, batch);
        resultText = repairText;
        yield { type: "thinking", message: "Pi JSON repair succeeded" };
      } catch (repairErr) {
        const combinedError = jsonRepairFailureError(err, repairErr);
        writeParseFailureDebug({
          projectId,
          phase: "investigate",
          agentType: this.type,
          resultText: formatJsonRepairFailureDebugText(resultText, repairText),
          error: combinedError,
          batch,
        });
        session?.dispose();
        throw combinedError;
      }
    }

    const refusal = await runRefusalFollowUp(session, signal);
    if (refusal?.refused) {
      yield {
        type: "thinking",
        message: `Refusal detected: ${refusal.reason ?? "see raw"}`,
      };
    }

    const costStr = sdkMeta.costUsd != null ? ` $${sdkMeta.costUsd.toFixed(3)}` : "";
    const tokensStr = sdkMeta.usage
      ? ` ${sdkMeta.usage.inputTokens + sdkMeta.usage.outputTokens} tokens`
      : "";
    yield {
      type: "complete",
      message: `Investigation complete (${(durationMs / 1000).toFixed(1)}s, ${turnCount} turns, ${toolUseCount} tool calls${costStr}${tokensStr}${refusal?.refused ? " refusal" : ""})`,
    };

    session?.dispose();
    return {
      results,
      meta: {
        durationMs,
        ...sdkMeta,
        refusal,
      },
    };
  }

  async *revalidate(params: RevalidateParams): AsyncGenerator<AgentProgress, RevalidateOutput> {
    const { batch, projectRoot, projectInfo, config, force = false, signal, projectId } = params;
    const cfg = readConfig(config);
    const maxTurns = cfg.maxTurns ?? 150;
    const { prompt, totalFindings } = buildRevalidatePrompt({
      batch,
      projectRoot,
      projectInfo,
      force,
    });
    const startTime = Date.now();

    let resultText = "";
    let lastError = "";
    let session: AgentSession | undefined;
    let modelLabel = cfg.model ?? DEFAULT_MODEL;
    let sdkMeta: Partial<BatchMeta> = {};
    let turnCount = 0;
    let toolUseCount = 0;

    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      if (attempt > 1) {
        yield {
          type: "thinking",
          message: `Retrying Pi revalidation after transient error (attempt ${attempt}/${MAX_ATTEMPTS}): ${lastError.slice(0, 200)}`,
        };
        session?.dispose();
        session = undefined;
        resultText = "";
        lastError = "";
        sdkMeta = {};
        turnCount = 0;
        toolUseCount = 0;
      }

      try {
        const setup = await createPiSession(projectRoot, cfg);
        session = setup.session;
        modelLabel = setup.modelLabel;
        if (attempt === 1) {
          yield {
            type: "started",
            message: `Revalidating ${totalFindings} finding(s) across ${batch.length} file(s) with Pi (${modelLabel})`,
          };
        }
        const run = yield* runPiPrompt({
          session,
          prompt,
          label: "revalidate",
          maxTurns,
          signal,
        });
        resultText = run.resultText;
        sdkMeta = run.meta;
        turnCount = run.turnCount;
        toolUseCount = run.toolUseCount;
      } catch (err) {
        lastError = err instanceof Error ? err.message : String(err);
        yield { type: "error", message: `Pi SDK error: ${lastError.slice(0, 300)}` };
      }

      if (resultText) break;
      const quotaSource = classifyQuotaError(lastError);
      if (quotaSource) {
        throw new QuotaExhaustedError(quotaSource, lastError);
      }
      if (attempt >= MAX_ATTEMPTS || !isTransientError(lastError)) break;
      await backoff(attempt);
    }

    if (!resultText) {
      session?.dispose();
      throw new Error(
        `Pi produced no revalidation result after ${MAX_ATTEMPTS} attempt(s). ` +
          `Last error: ${lastError || "(none captured)"}.`,
      );
    }

    const durationMs = Date.now() - startTime;
    let verdicts: RevalidateVerdict[];
    try {
      verdicts = parseRevalidateVerdicts(resultText);
    } catch (err) {
      yield {
        type: "thinking",
        message: "Pi returned non-JSON revalidation output; requesting JSON-only repair",
      };
      const repairText = await runToollessFollowUp(
        session,
        buildRevalidateJsonRepairPrompt(),
        signal,
      );
      if (repairText === undefined) {
        writeParseFailureDebug({
          projectId,
          phase: "revalidate",
          agentType: this.type,
          resultText,
          error: err,
          batch,
        });
        session?.dispose();
        throw err;
      }
      try {
        verdicts = parseRevalidateVerdicts(repairText);
        resultText = repairText;
        yield { type: "thinking", message: "Pi JSON repair succeeded" };
      } catch (repairErr) {
        const combinedError = jsonRepairFailureError(err, repairErr);
        writeParseFailureDebug({
          projectId,
          phase: "revalidate",
          agentType: this.type,
          resultText: formatJsonRepairFailureDebugText(resultText, repairText),
          error: combinedError,
          batch,
        });
        session?.dispose();
        throw combinedError;
      }
    }

    const refusal = await runRefusalFollowUp(session, signal);
    if (refusal?.refused) {
      yield {
        type: "thinking",
        message: `Refusal detected during revalidation: ${refusal.reason ?? "see raw"}`,
      };
    }

    const costStr = sdkMeta.costUsd != null ? ` $${sdkMeta.costUsd.toFixed(3)}` : "";
    yield {
      type: "complete",
      message: `Revalidation complete (${(durationMs / 1000).toFixed(1)}s, ${turnCount} turns, ${toolUseCount} tool calls${costStr}, ${verdicts.length} verdicts${refusal?.refused ? " refusal" : ""})`,
    };

    session?.dispose();
    return {
      verdicts,
      meta: { durationMs, ...sdkMeta, refusal },
    };
  }
}

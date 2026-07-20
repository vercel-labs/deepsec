import net from "node:net";
import type { RefusalReport } from "@deepsec/core";
import {
  type AssistantMessage,
  type Config,
  createOpencodeClient,
  createOpencodeServer,
  type OpencodeClient,
  type OutputFormat,
  type Part,
  type PermissionConfig,
} from "@opencode-ai/sdk/v2";
import { Agent as UndiciAgent, fetch as undiciFetch } from "undici";
import {
  backoff,
  buildInvestigateJsonRepairPrompt,
  buildInvestigatePrompt,
  buildRevalidateJsonRepairPrompt,
  buildRevalidatePrompt,
  classifyQuotaError,
  formatJsonRepairFailureDebugText,
  isTransientError,
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

const DEFAULT_MODEL = "anthropic/claude-opus-4-8";
const DEFAULT_THINKING_LEVEL = "xhigh";
const DEFAULT_MAX_TURNS = 150;
const MAIN_AGENT = "deepsec";
const JSON_AGENT = "deepsec-json";

const DEEPSEC_SYSTEM_NOTE =
  "You are running inside the OpenCode harness for deepsec. Perform static source inspection only. Do not run the target application, execute shell commands, send network requests, modify files, or attempt exploitation. Return only the requested JSON value.";

interface OpenCodeAgentConfig {
  model?: string;
  maxTurns?: number;
  thinkingLevel?: string;
  aiProvider?: string;
  aiBaseUrl?: string;
  aiApiKeyEnv?: string;
  aiHeaders?: Record<string, string>;
}

interface OpenCodeModelRef {
  providerID: string;
  modelID: string;
}

interface OpenCodeRunContext {
  client: OpencodeClient;
  server: { close(): void };
  dispatcher: UndiciAgent;
  sessionID: string;
  directory: string;
  controller: AbortController;
  detachParentAbort: () => void;
}

interface OpenCodePromptResult {
  resultText: string;
  meta: Partial<BatchMeta>;
  turnCount: number;
  toolUseCount: number;
  progress: AgentProgress[];
}

interface OpenCodeResolvedText {
  resultText: string;
  recoveredStructuredText: boolean;
}

const INVESTIGATE_FORMAT: OutputFormat = {
  type: "json_schema",
  retryCount: 2,
  schema: {
    type: "array",
    items: {
      type: "object",
      additionalProperties: false,
      required: ["filePath", "findings"],
      properties: {
        filePath: { type: "string" },
        findings: {
          type: "array",
          items: {
            type: "object",
            additionalProperties: false,
            required: [
              "severity",
              "vulnSlug",
              "title",
              "description",
              "lineNumbers",
              "recommendation",
              "confidence",
            ],
            properties: {
              severity: {
                type: "string",
                enum: ["CRITICAL", "HIGH", "MEDIUM", "HIGH_BUG", "BUG"],
              },
              vulnSlug: { type: "string" },
              title: { type: "string" },
              description: { type: "string" },
              lineNumbers: {
                type: "array",
                items: { type: "integer" },
              },
              recommendation: { type: "string" },
              confidence: {
                type: "string",
                enum: ["high", "medium", "low"],
              },
            },
          },
        },
      },
    },
  },
};

const REVALIDATE_FORMAT: OutputFormat = {
  type: "json_schema",
  retryCount: 2,
  schema: {
    type: "array",
    items: {
      type: "object",
      additionalProperties: false,
      required: ["filePath", "title", "verdict", "reasoning"],
      properties: {
        filePath: { type: "string" },
        title: { type: "string" },
        verdict: {
          type: "string",
          enum: ["true-positive", "false-positive", "fixed", "uncertain", "duplicate"],
        },
        reasoning: { type: "string" },
        adjustedSeverity: {
          type: "string",
          enum: ["CRITICAL", "HIGH", "MEDIUM", "HIGH_BUG", "BUG"],
        },
        duplicateOf: { type: "string" },
      },
    },
  },
};

const TEXT_FORMAT: OutputFormat = { type: "text" };

const READ_ONLY_PERMISSION: PermissionConfig = {
  "*": "deny",
  read: "allow",
  glob: "allow",
  grep: "allow",
  list: "allow",
  external_directory: "deny",
  bash: "deny",
  edit: "deny",
  task: "deny",
  todowrite: "deny",
  question: "deny",
  webfetch: "deny",
  websearch: "deny",
  lsp: "deny",
  skill: "deny",
  doom_loop: "allow",
};

const READ_ONLY_TOOLS: Record<string, boolean> = {
  read: true,
  glob: true,
  grep: true,
  list: true,
  bash: false,
  edit: false,
  write: false,
  patch: false,
  task: false,
  todowrite: false,
  question: false,
  webfetch: false,
  websearch: false,
  lsp: false,
  skill: false,
};

const NO_TOOLS = Object.fromEntries(Object.keys(READ_ONLY_TOOLS).map((name) => [name, false]));

function readConfig(config: Record<string, unknown>): OpenCodeAgentConfig {
  return {
    model: typeof config.model === "string" ? config.model : undefined,
    maxTurns: typeof config.maxTurns === "number" ? config.maxTurns : undefined,
    thinkingLevel: typeof config.thinkingLevel === "string" ? config.thinkingLevel : undefined,
    aiProvider: typeof config.aiProvider === "string" ? config.aiProvider : undefined,
    aiBaseUrl: typeof config.aiBaseUrl === "string" ? config.aiBaseUrl : undefined,
    aiApiKeyEnv: typeof config.aiApiKeyEnv === "string" ? config.aiApiKeyEnv : undefined,
    aiHeaders:
      config.aiHeaders && typeof config.aiHeaders === "object" && !Array.isArray(config.aiHeaders)
        ? (config.aiHeaders as Record<string, string>)
        : undefined,
  };
}

export function parseOpenCodeModel(model: string): OpenCodeModelRef {
  const slash = model.indexOf("/");
  if (slash <= 0 || slash === model.length - 1) {
    throw new Error(
      `OpenCode model must use provider/model format, got "${model}". ` +
        `For example: ${DEFAULT_MODEL}.`,
    );
  }
  return {
    providerID: model.slice(0, slash),
    modelID: model.slice(slash + 1),
  };
}

export function resolveOpenCodeVariant(
  providerID: string,
  thinkingLevel?: string,
): string | undefined {
  const explicit = thinkingLevel !== undefined;
  const level = thinkingLevel ?? DEFAULT_THINKING_LEVEL;
  const provider = providerID.toLowerCase();

  if (provider === "anthropic") return level === "xhigh" ? "max" : "high";
  if (provider === "openai") return level;
  if (provider === "google") {
    return level === "minimal" || level === "low" ? "low" : "high";
  }
  return explicit ? level : undefined;
}

export function shouldUseOpenCodeTextFormat(
  providerID: string,
  variant: string | undefined,
  format: OutputFormat,
): boolean {
  return (
    providerID.toLowerCase() === "anthropic" && Boolean(variant) && format.type === "json_schema"
  );
}

function providerCredentialEnv(providerID: string, cfg: OpenCodeAgentConfig): string | undefined {
  if (cfg.aiApiKeyEnv) return cfg.aiApiKeyEnv;
  if (providerID === "anthropic") {
    if (process.env.ANTHROPIC_AUTH_TOKEN) return "ANTHROPIC_AUTH_TOKEN";
    if (process.env.ANTHROPIC_API_KEY) return "ANTHROPIC_API_KEY";
  }
  if (providerID === "openai" && process.env.OPENAI_API_KEY) return "OPENAI_API_KEY";
  return undefined;
}

function anthropicBaseUrlForOpenCode(baseURL: string | undefined): string | undefined {
  if (!baseURL) return undefined;
  const normalized = baseURL.replace(/\/+$/, "");
  return normalized.endsWith("/v1") ? normalized : `${normalized}/v1`;
}

export function buildOpenCodeConfig(config: Record<string, unknown>): Config {
  const cfg = readConfig(config);
  const requested = parseOpenCodeModel(cfg.model ?? DEFAULT_MODEL);
  const providerID = cfg.aiProvider ?? requested.providerID;
  const model = `${providerID}/${requested.modelID}`;
  const variant = resolveOpenCodeVariant(providerID, cfg.thinkingLevel);
  const maxTurns = cfg.maxTurns ?? DEFAULT_MAX_TURNS;
  const credentialEnv = providerCredentialEnv(providerID, cfg);
  const baseURL =
    cfg.aiBaseUrl ??
    (providerID === "anthropic"
      ? anthropicBaseUrlForOpenCode(process.env.ANTHROPIC_BASE_URL)
      : providerID === "openai"
        ? process.env.OPENAI_BASE_URL
        : undefined);

  const providerOptions: Record<string, unknown> = {};
  if (credentialEnv) providerOptions.apiKey = `{env:${credentialEnv}}`;
  if (baseURL) providerOptions.baseURL = baseURL;

  const provider =
    Object.keys(providerOptions).length > 0 || cfg.aiHeaders
      ? {
          [providerID]: {
            ...(Object.keys(providerOptions).length > 0 ? { options: providerOptions } : {}),
            ...(cfg.aiHeaders ? { headers: cfg.aiHeaders } : {}),
          },
        }
      : undefined;

  return {
    logLevel: "WARN",
    autoupdate: false,
    share: "disabled",
    snapshot: false,
    formatter: false,
    lsp: false,
    plugin: [],
    instructions: [],
    mcp: {},
    model,
    default_agent: MAIN_AGENT,
    permission: READ_ONLY_PERMISSION,
    tools: READ_ONLY_TOOLS,
    ...(provider ? { provider } : {}),
    agent: {
      [MAIN_AGENT]: {
        description: "Read-only static security analysis for deepsec",
        mode: "primary",
        model,
        ...(variant ? { variant } : {}),
        steps: maxTurns,
        prompt: DEEPSEC_SYSTEM_NOTE,
        tools: READ_ONLY_TOOLS,
        permission: READ_ONLY_PERMISSION,
      },
      [JSON_AGENT]: {
        description: "Tool-free JSON formatting follow-up for deepsec",
        mode: "primary",
        hidden: true,
        model,
        ...(variant ? { variant } : {}),
        steps: 1,
        prompt: "Return only the JSON value requested by the user. Do not use tools.",
        tools: NO_TOOLS,
        permission: "deny",
      },
    },
  };
}

async function findFreePort(): Promise<number> {
  return await new Promise<number>((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        server.close();
        reject(new Error("OpenCode could not allocate a local server port"));
        return;
      }
      const port = address.port;
      server.close((err) => {
        if (err) reject(err);
        else resolve(port);
      });
    });
  });
}

function createOpenCodeFetch(dispatcher: UndiciAgent): typeof globalThis.fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    // The generated SDK constructs Node's built-in Request, while the
    // separately versioned Undici package has its own branded Request class.
    // Normalize to primitives so fetch and its dispatcher always come from
    // the same Undici version.
    const request = input instanceof Request ? input : new Request(input, init);
    const body =
      request.method === "GET" || request.method === "HEAD"
        ? undefined
        : new Uint8Array(await request.arrayBuffer());
    return (await undiciFetch(request.url, {
      method: request.method,
      headers: Object.fromEntries(request.headers.entries()),
      body,
      redirect: request.redirect,
      signal: request.signal,
      dispatcher,
    })) as unknown as Response;
  }) as typeof globalThis.fetch;
}

async function createRunContext(params: {
  projectRoot: string;
  config: Record<string, unknown>;
  signal?: AbortSignal;
  title: string;
}): Promise<OpenCodeRunContext> {
  const controller = new AbortController();
  const onParentAbort = () =>
    controller.abort(params.signal?.reason ?? new Error("OpenCode run aborted"));
  if (params.signal) {
    if (params.signal.aborted) onParentAbort();
    else params.signal.addEventListener("abort", onParentAbort, { once: true });
  }
  const detachParentAbort = () => params.signal?.removeEventListener("abort", onParentAbort);

  let server: { url: string; close(): void } | undefined;
  const dispatcher = new UndiciAgent({
    // session.prompt is synchronous: OpenCode does not send response headers
    // until the entire agent loop finishes. Undici's 300-second defaults turn
    // valid long-running batches into a misleading `fetch failed`.
    headersTimeout: 0,
    bodyTimeout: 0,
  });
  try {
    const port = await findFreePort();
    server = await createOpencodeServer({
      hostname: "127.0.0.1",
      port,
      timeout: 15_000,
      signal: controller.signal,
      config: buildOpenCodeConfig(params.config),
    });
    const client = createOpencodeClient({
      baseUrl: server.url,
      fetch: createOpenCodeFetch(dispatcher),
    });

    const cfg = readConfig(params.config);
    const requested = parseOpenCodeModel(cfg.model ?? DEFAULT_MODEL);
    const providerID = cfg.aiProvider ?? requested.providerID;
    const variant = resolveOpenCodeVariant(providerID, cfg.thinkingLevel);
    const created = await client.session.create(
      {
        directory: params.projectRoot,
        title: params.title,
        agent: MAIN_AGENT,
        model: {
          providerID,
          id: requested.modelID,
          ...(variant ? { variant } : {}),
        },
      },
      { throwOnError: true, signal: controller.signal },
    );

    return {
      client,
      server,
      dispatcher,
      sessionID: created.data.id,
      directory: params.projectRoot,
      controller,
      detachParentAbort,
    };
  } catch (err) {
    server?.close();
    await dispatcher.close().catch(() => undefined);
    detachParentAbort();
    throw err;
  }
}

async function disposeRunContext(context: OpenCodeRunContext | undefined): Promise<void> {
  if (!context) return;
  context.detachParentAbort();
  if (!context.controller.signal.aborted) {
    try {
      await context.client.session.delete(
        { sessionID: context.sessionID, directory: context.directory },
        { throwOnError: true },
      );
    } catch {
      // Best effort: server shutdown is the authoritative cleanup.
    }
  }
  context.server.close();
  await context.dispatcher.close();
}

function formatAssistantError(error: NonNullable<AssistantMessage["error"]>): string {
  const message =
    error.data && typeof error.data === "object" && "message" in error.data
      ? String(error.data.message)
      : JSON.stringify(error.data);
  return `${error.name}: ${message}`;
}

function assistantError(error: NonNullable<AssistantMessage["error"]>): Error {
  const result = new Error(formatAssistantError(error));
  result.name = error.name;
  return result;
}

function isStructuredOutputError(error: unknown): boolean {
  return error instanceof Error && error.name === "StructuredOutputError";
}

export function formatOpenCodeError(error: unknown): string {
  if (!(error instanceof Error)) return String(error);

  const messages = [error.message];
  let cause: unknown = error.cause;
  const seen = new Set<unknown>([error]);
  while (cause instanceof Error && !seen.has(cause)) {
    seen.add(cause);
    const code =
      "code" in cause && typeof cause.code === "string" && cause.code ? ` (${cause.code})` : "";
    const message = `${cause.message}${code}`;
    if (!messages.includes(message)) messages.push(message);
    cause = cause.cause;
  }
  return messages.join(": ");
}

export function resolveOpenCodeAssistantText(
  info: Pick<AssistantMessage, "structured" | "error">,
  partText: string,
): OpenCodeResolvedText {
  if (info.structured !== undefined) {
    return {
      resultText: JSON.stringify(info.structured),
      recoveredStructuredText: false,
    };
  }
  if (!info.error) {
    return {
      resultText: partText,
      recoveredStructuredText: false,
    };
  }
  if (info.error.name === "StructuredOutputError" && partText) {
    return {
      resultText: partText,
      recoveredStructuredText: true,
    };
  }
  throw assistantError(info.error);
}

function textFromParts(parts: Part[]): string {
  const text: string[] = [];
  for (const part of parts) {
    if (part.type === "text" && !part.ignored) text.push(part.text);
  }
  return text.join("\n").trim();
}

function shortToolTarget(part: Extract<Part, { type: "tool" }>): string | undefined {
  const input = part.state.input;
  for (const key of ["path", "filePath", "file_path", "pattern", "query"]) {
    const value = input[key];
    if (typeof value === "string" && value.trim()) {
      return value.split("/").slice(-3).join("/");
    }
  }
  return undefined;
}

function progressFromParts(parts: Part[]): AgentProgress[] {
  const progress: AgentProgress[] = [];
  for (const part of parts) {
    if (part.type === "tool") {
      const target = shortToolTarget(part);
      progress.push({
        type: part.state.status === "error" ? "error" : "tool_use",
        message:
          part.state.status === "error"
            ? `OpenCode ${part.tool} error${target ? `: ${target}` : ""}: ${part.state.error.slice(0, 300)}`
            : `${part.tool}${target ? `: ${target}` : ""}`,
        candidateFile: target,
      });
    } else if (part.type === "retry") {
      progress.push({
        type: "thinking",
        message: `OpenCode provider retry ${part.attempt}: ${part.error.data.message.slice(0, 200)}`,
      });
    } else if (part.type === "compaction") {
      progress.push({ type: "thinking", message: "OpenCode compacted conversation context" });
    }
  }
  return progress;
}

async function runPrompt(params: {
  context: OpenCodeRunContext;
  prompt: string;
  format: OutputFormat;
  config: Record<string, unknown>;
  tools?: Record<string, boolean>;
  agent?: string;
}): Promise<OpenCodePromptResult> {
  const cfg = readConfig(params.config);
  const requested = parseOpenCodeModel(cfg.model ?? DEFAULT_MODEL);
  const providerID = cfg.aiProvider ?? requested.providerID;
  const variant = resolveOpenCodeVariant(providerID, cfg.thinkingLevel);
  const useTextFormat = shouldUseOpenCodeTextFormat(providerID, variant, params.format);
  const startTime = Date.now();

  const response = await params.context.client.session.prompt(
    {
      sessionID: params.context.sessionID,
      directory: params.context.directory,
      model: { providerID, modelID: requested.modelID },
      agent: params.agent ?? MAIN_AGENT,
      ...(variant ? { variant } : {}),
      tools: params.tools ?? READ_ONLY_TOOLS,
      format: useTextFormat ? TEXT_FORMAT : params.format,
      parts: [{ type: "text", text: params.prompt }],
    },
    { throwOnError: true, signal: params.context.controller.signal },
  );

  const { info, parts } = response.data;
  const resolved = resolveOpenCodeAssistantText(info, textFromParts(parts));
  const turnCount = Math.max(1, parts.filter((part) => part.type === "step-finish").length);
  const toolUseCount = parts.filter((part) => part.type === "tool").length;
  const completed = info.time.completed ?? Date.now();
  const progress = progressFromParts(parts);
  if (useTextFormat) {
    progress.push({
      type: "thinking",
      message:
        "Anthropic thinking is incompatible with forced StructuredOutput; validating the text response",
    });
  }
  if (resolved.recoveredStructuredText) {
    progress.push({
      type: "thinking",
      message:
        "OpenCode returned text instead of calling StructuredOutput; validating the text response",
    });
  }

  return {
    resultText: resolved.resultText,
    turnCount,
    toolUseCount,
    progress,
    meta: {
      durationApiMs: Math.max(0, completed - info.time.created),
      numTurns: turnCount,
      costUsd: info.cost,
      agentSessionId: info.sessionID,
      usage: {
        inputTokens: info.tokens.input,
        outputTokens: info.tokens.output,
        cacheReadInputTokens: info.tokens.cache.read,
        cacheCreationInputTokens: info.tokens.cache.write,
      },
      durationMs: Date.now() - startTime,
    },
  };
}

async function runToollessFollowUp(params: {
  context: OpenCodeRunContext | undefined;
  prompt: string;
  config: Record<string, unknown>;
}): Promise<string | undefined> {
  if (!params.context) return undefined;
  try {
    const result = await runPrompt({
      context: params.context,
      prompt: params.prompt,
      format: TEXT_FORMAT,
      config: params.config,
      tools: NO_TOOLS,
      agent: JSON_AGENT,
    });
    return result.resultText;
  } catch {
    return undefined;
  }
}

async function runRefusalFollowUp(params: {
  context: OpenCodeRunContext | undefined;
  config: Record<string, unknown>;
}): Promise<RefusalReport | undefined> {
  const raw = await runToollessFollowUp({
    ...params,
    prompt: REFUSAL_FOLLOWUP_PROMPT,
  });
  return raw === undefined ? undefined : parseRefusalReport(raw);
}

export class OpenCodeAgentPlugin implements AgentPlugin {
  type = "opencode";

  async *investigate(params: InvestigateParams): AsyncGenerator<AgentProgress, InvestigateOutput> {
    const { batch, projectRoot, promptTemplate, projectInfo, config, signal, projectId } = params;
    const prompt = buildInvestigatePrompt({ promptTemplate, projectInfo, batch });
    const model = readConfig(config).model ?? DEFAULT_MODEL;
    const startTime = Date.now();
    let context: OpenCodeRunContext | undefined;
    let resultText = "";
    let lastError = "";
    let sdkMeta: Partial<BatchMeta> = {};
    let turnCount = 0;
    let toolUseCount = 0;
    let attempts = 0;

    try {
      for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        attempts = attempt;
        if (attempt > 1) {
          yield {
            type: "thinking",
            message: `Retrying OpenCode batch after transient error (attempt ${attempt}/${MAX_ATTEMPTS}): ${lastError.slice(0, 200)}`,
          };
          await disposeRunContext(context);
          context = undefined;
          resultText = "";
          lastError = "";
          sdkMeta = {};
          turnCount = 0;
          toolUseCount = 0;
        }

        try {
          context = await createRunContext({
            projectRoot,
            config,
            signal,
            title: `deepsec investigate (${batch.length} files)`,
          });
          if (attempt === 1) {
            yield {
              type: "started",
              message: `Investigating ${batch.length} file(s) with OpenCode (${model})`,
            };
          }
          const run = await runPrompt({
            context,
            prompt,
            format: INVESTIGATE_FORMAT,
            config,
          });
          resultText = run.resultText;
          sdkMeta = run.meta;
          turnCount = run.turnCount;
          toolUseCount = run.toolUseCount;
          for (const progress of run.progress) yield progress;
        } catch (err) {
          if (isStructuredOutputError(err)) {
            yield {
              type: "thinking",
              message:
                "OpenCode did not call StructuredOutput; requesting a tool-free JSON finalization",
            };
            const recovered = await runToollessFollowUp({
              context,
              prompt: buildInvestigateJsonRepairPrompt(batch),
              config,
            });
            if (recovered) resultText = recovered;
          }
          if (!resultText) {
            lastError = formatOpenCodeError(err);
            yield { type: "error", message: `OpenCode SDK error: ${lastError.slice(0, 300)}` };
          }
        }

        if (resultText) break;
        const quotaSource = classifyQuotaError(lastError);
        if (quotaSource) throw new QuotaExhaustedError(quotaSource, lastError);
        if (attempt >= MAX_ATTEMPTS || !isTransientError(lastError)) break;
        await backoff(attempt);
      }

      if (!resultText) {
        throw new Error(
          `OpenCode produced no investigation result after ${attempts} attempt(s). ` +
            `Last error: ${lastError || "(none captured)"}.`,
        );
      }

      let results: InvestigateResult[];
      try {
        results = parseInvestigateResults(resultText, batch);
      } catch (err) {
        yield {
          type: "thinking",
          message: "OpenCode returned non-JSON investigation output; requesting JSON-only repair",
        };
        const repairText = await runToollessFollowUp({
          context,
          prompt: buildInvestigateJsonRepairPrompt(batch),
          config,
        });
        if (repairText === undefined) {
          writeParseFailureDebug({
            projectId,
            phase: "investigate",
            agentType: this.type,
            resultText,
            error: err,
            batch,
          });
          throw err;
        }
        try {
          results = parseInvestigateResults(repairText, batch);
          resultText = repairText;
          yield { type: "thinking", message: "OpenCode JSON repair succeeded" };
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
          throw combinedError;
        }
      }

      const refusal = await runRefusalFollowUp({ context, config });
      if (refusal?.refused) {
        yield {
          type: "thinking",
          message: `Refusal detected: ${refusal.reason ?? "see raw"}`,
        };
      }

      const durationMs = Date.now() - startTime;
      const costStr = sdkMeta.costUsd != null ? ` $${sdkMeta.costUsd.toFixed(3)}` : "";
      const tokensStr = sdkMeta.usage
        ? ` ${sdkMeta.usage.inputTokens + sdkMeta.usage.outputTokens} tokens`
        : "";
      yield {
        type: "complete",
        message: `Investigation complete (${(durationMs / 1000).toFixed(1)}s, ${turnCount} turns, ${toolUseCount} tool calls${costStr}${tokensStr}${refusal?.refused ? " refusal" : ""})`,
      };

      return {
        results,
        meta: {
          durationMs,
          ...sdkMeta,
          refusal,
        },
      };
    } finally {
      await disposeRunContext(context);
    }
  }

  async *revalidate(params: RevalidateParams): AsyncGenerator<AgentProgress, RevalidateOutput> {
    const { batch, projectRoot, projectInfo, config, force = false, signal, projectId } = params;
    const { prompt, totalFindings } = buildRevalidatePrompt({
      batch,
      projectRoot,
      projectInfo,
      force,
    });
    const model = readConfig(config).model ?? DEFAULT_MODEL;
    const startTime = Date.now();
    let context: OpenCodeRunContext | undefined;
    let resultText = "";
    let lastError = "";
    let sdkMeta: Partial<BatchMeta> = {};
    let turnCount = 0;
    let toolUseCount = 0;
    let attempts = 0;

    try {
      for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        attempts = attempt;
        if (attempt > 1) {
          yield {
            type: "thinking",
            message: `Retrying OpenCode revalidation after transient error (attempt ${attempt}/${MAX_ATTEMPTS}): ${lastError.slice(0, 200)}`,
          };
          await disposeRunContext(context);
          context = undefined;
          resultText = "";
          lastError = "";
          sdkMeta = {};
          turnCount = 0;
          toolUseCount = 0;
        }

        try {
          context = await createRunContext({
            projectRoot,
            config,
            signal,
            title: `deepsec revalidate (${totalFindings} findings)`,
          });
          if (attempt === 1) {
            yield {
              type: "started",
              message: `Revalidating ${totalFindings} finding(s) across ${batch.length} file(s) with OpenCode (${model})`,
            };
          }
          const run = await runPrompt({
            context,
            prompt,
            format: REVALIDATE_FORMAT,
            config,
          });
          resultText = run.resultText;
          sdkMeta = run.meta;
          turnCount = run.turnCount;
          toolUseCount = run.toolUseCount;
          for (const progress of run.progress) yield progress;
        } catch (err) {
          if (isStructuredOutputError(err)) {
            yield {
              type: "thinking",
              message:
                "OpenCode did not call StructuredOutput; requesting a tool-free JSON finalization",
            };
            const recovered = await runToollessFollowUp({
              context,
              prompt: buildRevalidateJsonRepairPrompt(),
              config,
            });
            if (recovered) resultText = recovered;
          }
          if (!resultText) {
            lastError = formatOpenCodeError(err);
            yield { type: "error", message: `OpenCode SDK error: ${lastError.slice(0, 300)}` };
          }
        }

        if (resultText) break;
        const quotaSource = classifyQuotaError(lastError);
        if (quotaSource) throw new QuotaExhaustedError(quotaSource, lastError);
        if (attempt >= MAX_ATTEMPTS || !isTransientError(lastError)) break;
        await backoff(attempt);
      }

      if (!resultText) {
        throw new Error(
          `OpenCode produced no revalidation result after ${attempts} attempt(s). ` +
            `Last error: ${lastError || "(none captured)"}.`,
        );
      }

      let verdicts: RevalidateVerdict[];
      try {
        verdicts = parseRevalidateVerdicts(resultText);
      } catch (err) {
        yield {
          type: "thinking",
          message: "OpenCode returned non-JSON revalidation output; requesting JSON-only repair",
        };
        const repairText = await runToollessFollowUp({
          context,
          prompt: buildRevalidateJsonRepairPrompt(),
          config,
        });
        if (repairText === undefined) {
          writeParseFailureDebug({
            projectId,
            phase: "revalidate",
            agentType: this.type,
            resultText,
            error: err,
            batch,
          });
          throw err;
        }
        try {
          verdicts = parseRevalidateVerdicts(repairText);
          resultText = repairText;
          yield { type: "thinking", message: "OpenCode JSON repair succeeded" };
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
          throw combinedError;
        }
      }

      const refusal = await runRefusalFollowUp({ context, config });
      if (refusal?.refused) {
        yield {
          type: "thinking",
          message: `Refusal detected during revalidation: ${refusal.reason ?? "see raw"}`,
        };
      }

      const durationMs = Date.now() - startTime;
      const costStr = sdkMeta.costUsd != null ? ` $${sdkMeta.costUsd.toFixed(3)}` : "";
      yield {
        type: "complete",
        message: `Revalidation complete (${(durationMs / 1000).toFixed(1)}s, ${turnCount} turns, ${toolUseCount} tool calls${costStr}, ${verdicts.length} verdicts${refusal?.refused ? " refusal" : ""})`,
      };

      return {
        verdicts,
        meta: { durationMs, ...sdkMeta, refusal },
      };
    } finally {
      await disposeRunContext(context);
    }
  }
}

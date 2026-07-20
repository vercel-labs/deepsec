import net from "node:net";
import type { RefusalReport } from "@deepsec/core";
import {
  type AssistantMessage,
  type Config,
  createOpencode,
  type OpencodeClient,
  type OutputFormat,
  type Part,
  type PermissionConfig,
} from "@opencode-ai/sdk/v2";
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

const REFUSAL_FORMAT: OutputFormat = {
  type: "json_schema",
  retryCount: 1,
  schema: {
    type: "object",
    additionalProperties: false,
    required: ["refused", "skipped"],
    properties: {
      refused: { type: "boolean" },
      reason: { type: ["string", "null"] },
      skipped: {
        type: "array",
        items: {
          type: "object",
          additionalProperties: false,
          required: ["reason"],
          properties: {
            filePath: { type: "string" },
            reason: { type: "string" },
          },
        },
      },
    },
  },
};

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

function providerCredentialEnv(providerID: string, cfg: OpenCodeAgentConfig): string | undefined {
  if (cfg.aiApiKeyEnv) return cfg.aiApiKeyEnv;
  if (providerID === "anthropic") {
    if (process.env.ANTHROPIC_AUTH_TOKEN) return "ANTHROPIC_AUTH_TOKEN";
    if (process.env.ANTHROPIC_API_KEY) return "ANTHROPIC_API_KEY";
  }
  if (providerID === "openai" && process.env.OPENAI_API_KEY) return "OPENAI_API_KEY";
  return undefined;
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
      ? process.env.ANTHROPIC_BASE_URL
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

  let server: { close(): void } | undefined;
  try {
    const port = await findFreePort();
    const started = await createOpencode({
      hostname: "127.0.0.1",
      port,
      timeout: 15_000,
      signal: controller.signal,
      config: buildOpenCodeConfig(params.config),
    });
    server = started.server;

    const cfg = readConfig(params.config);
    const requested = parseOpenCodeModel(cfg.model ?? DEFAULT_MODEL);
    const providerID = cfg.aiProvider ?? requested.providerID;
    const variant = resolveOpenCodeVariant(providerID, cfg.thinkingLevel);
    const created = await started.client.session.create(
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
      client: started.client,
      server: started.server,
      sessionID: created.data.id,
      directory: params.projectRoot,
      controller,
      detachParentAbort,
    };
  } catch (err) {
    server?.close();
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
}

function formatAssistantError(error: NonNullable<AssistantMessage["error"]>): string {
  const message =
    error.data && typeof error.data === "object" && "message" in error.data
      ? String(error.data.message)
      : JSON.stringify(error.data);
  return `${error.name}: ${message}`;
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
  const startTime = Date.now();

  const response = await params.context.client.session.prompt(
    {
      sessionID: params.context.sessionID,
      directory: params.context.directory,
      model: { providerID, modelID: requested.modelID },
      agent: params.agent ?? MAIN_AGENT,
      ...(variant ? { variant } : {}),
      tools: params.tools ?? READ_ONLY_TOOLS,
      format: params.format,
      parts: [{ type: "text", text: params.prompt }],
    },
    { throwOnError: true, signal: params.context.controller.signal },
  );

  const { info, parts } = response.data;
  if (info.error) throw new Error(formatAssistantError(info.error));

  const resultText =
    info.structured !== undefined ? JSON.stringify(info.structured) : textFromParts(parts);
  const turnCount = Math.max(1, parts.filter((part) => part.type === "step-finish").length);
  const toolUseCount = parts.filter((part) => part.type === "tool").length;
  const completed = info.time.completed ?? Date.now();

  return {
    resultText,
    turnCount,
    toolUseCount,
    progress: progressFromParts(parts),
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
  format: OutputFormat;
  config: Record<string, unknown>;
}): Promise<string | undefined> {
  if (!params.context) return undefined;
  try {
    const result = await runPrompt({
      context: params.context,
      prompt: params.prompt,
      format: params.format,
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
    format: REFUSAL_FORMAT,
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

    try {
      for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
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
          lastError = err instanceof Error ? err.message : String(err);
          yield { type: "error", message: `OpenCode SDK error: ${lastError.slice(0, 300)}` };
        }

        if (resultText) break;
        const quotaSource = classifyQuotaError(lastError);
        if (quotaSource) throw new QuotaExhaustedError(quotaSource, lastError);
        if (attempt >= MAX_ATTEMPTS || !isTransientError(lastError)) break;
        await backoff(attempt);
      }

      if (!resultText) {
        throw new Error(
          `OpenCode produced no investigation result after ${MAX_ATTEMPTS} attempt(s). ` +
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
          format: INVESTIGATE_FORMAT,
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

    try {
      for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
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
          lastError = err instanceof Error ? err.message : String(err);
          yield { type: "error", message: `OpenCode SDK error: ${lastError.slice(0, 300)}` };
        }

        if (resultText) break;
        const quotaSource = classifyQuotaError(lastError);
        if (quotaSource) throw new QuotaExhaustedError(quotaSource, lastError);
        if (attempt >= MAX_ATTEMPTS || !isTransientError(lastError)) break;
        await backoff(attempt);
      }

      if (!resultText) {
        throw new Error(
          `OpenCode produced no revalidation result after ${MAX_ATTEMPTS} attempt(s). ` +
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
          format: REVALIDATE_FORMAT,
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

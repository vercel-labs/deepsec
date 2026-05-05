import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import { Readable, Writable } from "node:stream";
import * as acp from "@agentclientprotocol/sdk";
import type { RefusalReport } from "@deepsec/core";
import {
  backoff,
  buildInvestigatePrompt,
  buildRevalidatePrompt,
  isTransientError,
  MAX_ATTEMPTS,
  parseInvestigateResults,
  parseRefusalReport,
  parseRevalidateVerdicts,
  REFUSAL_FOLLOWUP_PROMPT,
} from "./shared.js";
import type {
  AgentPlugin,
  AgentProgress,
  BatchMeta,
  InvestigateOutput,
  InvestigateParams,
  RevalidateOutput,
  RevalidateParams,
} from "./types.js";

const DEFAULT_MODEL = "acp-default";
const DEFAULT_ACP_REGISTRY_URL =
  "https://cdn.agentclientprotocol.com/registry/v1/latest/registry.json";
const DEBUG = process.env.DEEPSEC_AGENT_DEBUG === "1";

interface AcpConfig {
  model?: string;
  maxTurns?: number;
  /** Alta/Atlas source for `atlas alta agent run --workspace <root> <source>`. */
  acpAgent?: string;
  /** Registry agent id from https://agentclientprotocol.com, e.g. `claude-acp` or `codex-acp`. */
  acpRegistryAgent?: string;
  /** Registry JSON URL. Defaults to the public latest registry. */
  acpRegistryUrl?: string;
  /** Custom ACP bridge command. May be just an executable, or a quoted command string when acpArgs is omitted. */
  acpCommand?: string;
  acpArgs?: string[];
  acpEnv?: Record<string, string>;
}

interface AcpInvocation {
  command: string;
  args: string[];
  env?: Record<string, string>;
  label: string;
}

interface AcpRegistryAgent {
  id: string;
  name?: string;
  distribution?: {
    npx?: { package?: string; args?: string[]; env?: Record<string, string> };
    uvx?: { package?: string; args?: string[]; env?: Record<string, string> };
    binary?: unknown;
  };
}

interface AcpRegistry {
  agents?: AcpRegistryAgent[];
}

let registryCache: { url: string; registry: AcpRegistry } | undefined;

interface AcpTurnResult {
  text: string;
  sessionId?: string;
  stopReason?: string;
  turnCount: number;
  toolUseCount: number;
  meta: Partial<BatchMeta>;
}

function stringRecord(value: unknown): Record<string, string> | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).map(([k, v]) => [k, String(v)]),
  );
}

function asAcpConfig(config: Record<string, unknown>): AcpConfig {
  return {
    model: typeof config.model === "string" ? config.model : undefined,
    maxTurns: typeof config.maxTurns === "number" ? config.maxTurns : undefined,
    acpAgent: typeof config.acpAgent === "string" ? config.acpAgent : undefined,
    acpRegistryAgent:
      typeof config.acpRegistryAgent === "string" ? config.acpRegistryAgent : undefined,
    acpRegistryUrl: typeof config.acpRegistryUrl === "string" ? config.acpRegistryUrl : undefined,
    acpCommand: typeof config.acpCommand === "string" ? config.acpCommand : undefined,
    acpArgs: Array.isArray(config.acpArgs) ? config.acpArgs.map(String) : undefined,
    acpEnv: stringRecord(config.acpEnv),
  };
}

function splitCommandString(command: string): string[] {
  const parts: string[] = [];
  let current = "";
  let quote: '"' | "'" | undefined;
  let escaping = false;
  for (const ch of command.trim()) {
    if (escaping) {
      current += ch;
      escaping = false;
      continue;
    }
    if (ch === "\\") {
      escaping = true;
      continue;
    }
    if (quote) {
      if (ch === quote) quote = undefined;
      else current += ch;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (/\s/.test(ch)) {
      if (current) {
        parts.push(current);
        current = "";
      }
      continue;
    }
    current += ch;
  }
  if (escaping) current += "\\";
  if (quote) throw new Error(`Unterminated quote in --acp-command: ${command}`);
  if (current) parts.push(current);
  return parts;
}

function customInvocation(config: AcpConfig): AcpInvocation | undefined {
  if (!config.acpCommand) return undefined;
  if (config.acpArgs) {
    return {
      command: config.acpCommand,
      args: config.acpArgs,
      env: config.acpEnv,
      label: `${config.acpCommand} ${config.acpArgs.join(" ")}`,
    };
  }
  const parts = splitCommandString(config.acpCommand);
  if (parts.length === 0) throw new Error("--acp-command must not be empty");
  return { command: parts[0], args: parts.slice(1), env: config.acpEnv, label: config.acpCommand };
}

async function fetchRegistry(url: string): Promise<AcpRegistry> {
  if (registryCache?.url === url) return registryCache.registry;
  const response = await fetch(url);
  if (!response.ok) throw new Error(`Failed to fetch ACP registry ${url}: HTTP ${response.status}`);
  const registry = (await response.json()) as AcpRegistry;
  registryCache = { url, registry };
  return registry;
}

async function registryInvocation(config: AcpConfig): Promise<AcpInvocation | undefined> {
  if (!config.acpRegistryAgent) return undefined;
  const url = config.acpRegistryUrl ?? DEFAULT_ACP_REGISTRY_URL;
  const registry = await fetchRegistry(url);
  const entry = registry.agents?.find((agent) => agent.id === config.acpRegistryAgent);
  if (!entry) {
    const examples =
      registry.agents
        ?.slice(0, 8)
        .map((agent) => agent.id)
        .join(", ") ?? "none";
    throw new Error(
      `ACP registry agent not found: ${config.acpRegistryAgent}. Examples: ${examples}`,
    );
  }

  const npx = entry.distribution?.npx;
  if (npx?.package) {
    return {
      command: "npx",
      args: ["-y", npx.package, ...(npx.args ?? []).map(String)],
      env: { ...npx.env, ...config.acpEnv },
      label: `${entry.id} via registry npx (${npx.package})`,
    };
  }

  const uvx = entry.distribution?.uvx;
  if (uvx?.package) {
    return {
      command: "uvx",
      args: [uvx.package, ...(uvx.args ?? []).map(String)],
      env: { ...uvx.env, ...config.acpEnv },
      label: `${entry.id} via registry uvx (${uvx.package})`,
    };
  }

  if (entry.distribution?.binary) {
    throw new Error(
      `ACP registry agent ${entry.id} is binary-only. Install it first, then pass a custom bridge with --acp-command/--acp-args.`,
    );
  }

  throw new Error(`ACP registry agent ${entry.id} has no supported npx or uvx distribution.`);
}

export async function buildAcpInvocation(
  projectRoot: string,
  config: AcpConfig,
): Promise<AcpInvocation> {
  const custom = customInvocation(config);
  if (custom) return custom;
  const registry = await registryInvocation(config);
  if (registry) return registry;
  if (config.acpAgent) {
    return {
      command: "atlas",
      args: ["alta", "agent", "run", "--workspace", projectRoot, config.acpAgent],
      env: config.acpEnv,
      label: `atlas alta agent run ${config.acpAgent}`,
    };
  }

  throw new Error(
    "ACP agent selection is required. Pass --acp-registry-agent <id>, --acp-command <cmd>, or --acp-agent <source> for atlas alta agent run.",
  );
}

function shortToolMessage(update: Record<string, unknown>): string {
  const title = typeof update.title === "string" ? update.title : undefined;
  const status = typeof update.status === "string" ? update.status : undefined;
  const id = typeof update.toolCallId === "string" ? update.toolCallId : undefined;
  const base = title || id || "tool call";
  return status ? `${base} (${status})` : base;
}

function extractUsage(update: Record<string, unknown>): BatchMeta["usage"] | undefined {
  const usage = update.usage;
  if (!usage || typeof usage !== "object") return undefined;
  const u = usage as Record<string, unknown>;
  const inputTokens = Number(u.inputTokens ?? u.input_tokens ?? 0);
  const outputTokens = Number(u.outputTokens ?? u.output_tokens ?? 0);
  return {
    inputTokens: Number.isFinite(inputTokens) ? inputTokens : 0,
    outputTokens: Number.isFinite(outputTokens) ? outputTokens : 0,
    cacheReadInputTokens: Number(u.cacheReadInputTokens ?? u.cache_read_input_tokens ?? 0) || 0,
    cacheCreationInputTokens:
      Number(u.cacheCreationInputTokens ?? u.cache_creation_input_tokens ?? 0) || 0,
  };
}

class DeepsecAcpClient implements acp.Client {
  readonly textChunks: string[] = [];
  readonly progress: AgentProgress[] = [];
  turnCount = 0;
  toolUseCount = 0;
  usage: BatchMeta["usage"] | undefined;

  async requestPermission(
    params: acp.RequestPermissionRequest,
  ): Promise<acp.RequestPermissionResponse> {
    const reject =
      params.options.find((o) => o.kind === "reject_always") ??
      params.options.find((o) => o.kind === "reject_once");
    if (reject) {
      this.progress.push({
        type: "tool_use",
        message: `permission requested for ${params.toolCall.title ?? params.toolCall.toolCallId}; rejecting to keep deepsec read-only`,
      });
      return { outcome: { outcome: "selected", optionId: reject.optionId } };
    }
    return { outcome: { outcome: "cancelled" } };
  }

  async sessionUpdate(params: acp.SessionNotification): Promise<void> {
    const update = params.update as Record<string, unknown>;
    switch (update.sessionUpdate) {
      case "agent_message_chunk": {
        const content = update.content as Record<string, unknown> | undefined;
        if (content?.type === "text" && typeof content.text === "string") {
          this.textChunks.push(content.text);
        }
        break;
      }
      case "agent_thought_chunk":
        this.turnCount++;
        this.progress.push({ type: "thinking", message: `ACP agent thinking (${this.turnCount})` });
        break;
      case "tool_call":
      case "tool_call_update":
        this.toolUseCount++;
        this.progress.push({ type: "tool_use", message: shortToolMessage(update) });
        break;
      case "usage_update": {
        this.usage = extractUsage(update);
        break;
      }
    }
  }
}

async function killAgent(child: ChildProcessWithoutNullStreams): Promise<void> {
  if (child.exitCode !== null || child.killed) return;
  child.kill("SIGTERM");
  await new Promise((resolve) => setTimeout(resolve, 100));
  if (child.exitCode === null && !child.killed) child.kill("SIGKILL");
}

async function* runAcpPrompt(params: {
  projectRoot: string;
  prompt: string;
  config: AcpConfig;
}): AsyncGenerator<AgentProgress, AcpTurnResult> {
  const invocation = await buildAcpInvocation(params.projectRoot, params.config);
  const child = spawn(invocation.command, invocation.args, {
    cwd: params.projectRoot,
    env: { ...process.env, ...invocation.env },
    stdio: ["pipe", "pipe", "pipe"],
  });

  const stderrChunks: string[] = [];
  child.stderr.on("data", (chunk) => {
    const text = String(chunk);
    stderrChunks.push(text);
    if (DEBUG) console.error(`[deepsec:acp] ${text}`);
  });

  const client = new DeepsecAcpClient();
  const input = Writable.toWeb(child.stdin) as WritableStream<Uint8Array>;
  const output = Readable.toWeb(child.stdout) as ReadableStream<Uint8Array>;
  const stream = acp.ndJsonStream(input, output);
  const connection = new acp.ClientSideConnection(() => client, stream);

  let sessionId: string | undefined;
  try {
    await connection.initialize({
      protocolVersion: acp.PROTOCOL_VERSION,
      clientInfo: { name: "deepsec", version: "0.0.0" },
      clientCapabilities: { fs: { readTextFile: false, writeTextFile: false } },
    });

    const session = await connection.newSession({ cwd: params.projectRoot, mcpServers: [] });
    sessionId = session.sessionId;

    const promptPromise = connection.prompt({
      sessionId,
      prompt: [{ type: "text", text: params.prompt }],
    });

    while (true) {
      const done = await Promise.race([
        promptPromise.then(() => true),
        new Promise<false>((resolve) => setTimeout(() => resolve(false), 100)),
      ]);
      while (client.progress.length > 0) {
        yield client.progress.shift()!;
      }
      if (done) break;
    }

    const promptResult = await promptPromise;
    while (client.progress.length > 0) {
      yield client.progress.shift()!;
    }

    return {
      text: client.textChunks.join(""),
      sessionId,
      stopReason: promptResult.stopReason,
      turnCount: client.turnCount,
      toolUseCount: client.toolUseCount,
      meta: {
        agentSessionId: sessionId,
        numTurns: client.turnCount,
        usage: client.usage,
      },
    };
  } catch (err) {
    const stderr = stderrChunks.join("").trim();
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(stderr ? `${message}\nACP stderr:\n${stderr.slice(-3000)}` : message);
  } finally {
    await killAgent(child);
  }
}

async function collectAcpTurn(
  promptParams: { projectRoot: string; prompt: string; config: AcpConfig },
  onProgress?: (progress: AgentProgress) => void,
): Promise<AcpTurnResult> {
  const gen = runAcpPrompt(promptParams);
  let next = await gen.next();
  while (!next.done) {
    onProgress?.(next.value);
    next = await gen.next();
  }
  return next.value;
}

async function runRefusalFollowUp(
  projectRoot: string,
  config: AcpConfig,
): Promise<RefusalReport | undefined> {
  try {
    const result = await collectAcpTurn({ projectRoot, prompt: REFUSAL_FOLLOWUP_PROMPT, config });
    return parseRefusalReport(result.text);
  } catch {
    return undefined;
  }
}

export class AcpAgentPlugin implements AgentPlugin {
  type = "acp";

  async *investigate(params: InvestigateParams): AsyncGenerator<AgentProgress, InvestigateOutput> {
    const { batch, projectRoot, promptTemplate, projectInfo } = params;
    const config = asAcpConfig(params.config);
    const model = config.model ?? DEFAULT_MODEL;
    const agentName =
      config.acpRegistryAgent ?? config.acpAgent ?? config.acpCommand ?? "(not configured)";

    yield {
      type: "started",
      message: `Investigating ${batch.length} file(s) with ACP agent ${agentName} (${model})`,
    };

    const prompt = buildInvestigatePrompt({ promptTemplate, projectInfo, batch });
    const startTime = Date.now();
    let turn: AcpTurnResult | undefined;
    let lastError = "";

    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      if (attempt > 1) {
        yield {
          type: "thinking" as const,
          message: `Retrying ACP batch after transient error (attempt ${attempt}/${MAX_ATTEMPTS}): ${lastError.slice(0, 200)}`,
        };
        turn = undefined;
        lastError = "";
      }

      try {
        turn = yield* runAcpPrompt({ projectRoot, prompt, config });
      } catch (err) {
        lastError = err instanceof Error ? err.message : String(err);
        yield { type: "error" as const, message: `ACP agent error: ${lastError.slice(0, 300)}` };
      }

      if (turn?.text) break;
      if (attempt >= MAX_ATTEMPTS || !isTransientError(lastError)) break;
      await backoff(attempt);
    }

    const resultText = turn?.text ?? "";
    const durationMs = Date.now() - startTime;
    const refusal = await runRefusalFollowUp(projectRoot, config);
    if (refusal?.refused) {
      yield {
        type: "thinking" as const,
        message: `Refusal detected: ${refusal.reason ?? refusal.skipped?.map((s) => s.filePath ?? "?").join(", ") ?? "see raw"}`,
      };
    }

    const tokensStr = turn?.meta.usage
      ? ` ${turn.meta.usage.inputTokens + turn.meta.usage.outputTokens} tokens`
      : "";
    yield {
      type: "complete",
      message: `Investigation complete (${(durationMs / 1000).toFixed(1)}s, ${turn?.turnCount ?? 0} turns, ${turn?.toolUseCount ?? 0} tool calls${tokensStr}${refusal?.refused ? " ⚠️  refusal" : ""})`,
    };

    return {
      results: parseInvestigateResults(resultText, batch),
      meta: { durationMs, ...turn?.meta, refusal },
    };
  }

  async *revalidate(params: RevalidateParams): AsyncGenerator<AgentProgress, RevalidateOutput> {
    const { batch, projectRoot, projectInfo, force = false } = params;
    const config = asAcpConfig(params.config);
    const model = config.model ?? DEFAULT_MODEL;
    const built = buildRevalidatePrompt({ batch, projectRoot, projectInfo, force });

    yield {
      type: "started",
      message: `Revalidating ${built.totalFindings} finding(s) across ${batch.length} file(s) with ACP (${model})`,
    };

    const startTime = Date.now();
    let turn: AcpTurnResult | undefined;
    let lastError = "";

    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      if (attempt > 1) {
        yield {
          type: "thinking" as const,
          message: `Retrying ACP revalidation after transient error (attempt ${attempt}/${MAX_ATTEMPTS}): ${lastError.slice(0, 200)}`,
        };
        turn = undefined;
        lastError = "";
      }

      try {
        turn = yield* runAcpPrompt({ projectRoot, prompt: built.prompt, config });
      } catch (err) {
        lastError = err instanceof Error ? err.message : String(err);
        yield { type: "error" as const, message: `ACP agent error: ${lastError.slice(0, 300)}` };
      }

      if (turn?.text) break;
      if (attempt >= MAX_ATTEMPTS || !isTransientError(lastError)) break;
      await backoff(attempt);
    }

    const resultText = turn?.text ?? "";
    const verdicts = parseRevalidateVerdicts(resultText);
    const durationMs = Date.now() - startTime;
    const refusal = await runRefusalFollowUp(projectRoot, config);
    if (refusal?.refused) {
      yield {
        type: "thinking" as const,
        message: `Refusal detected during revalidation: ${refusal.reason ?? "see raw"}`,
      };
    }

    yield {
      type: "complete",
      message: `Revalidation complete (${(durationMs / 1000).toFixed(1)}s, ${turn?.turnCount ?? 0} turns, ${verdicts.length} verdicts${refusal?.refused ? " ⚠️  refusal" : ""})`,
    };

    return {
      verdicts,
      meta: { durationMs, ...turn?.meta, refusal },
    };
  }
}

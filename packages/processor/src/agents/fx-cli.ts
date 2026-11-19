import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { RefusalReport } from "@deepsec/core";
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
  type ParsedInvestigateResults,
  parseInvestigateResults,
  parseRefusalReport,
  parseRevalidateVerdicts,
  QuotaExhaustedError,
  REFUSAL_FOLLOWUP_PROMPT,
  runInvestigateFieldRepairLoop,
  runRevalidateIdRepairLoop,
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
  RevalidateRawResponse,
  RevalidateVerdict,
  SetupTaskParams,
} from "./types.js";

/**
 * fx (https://fx.sh) as a Deepsec agent backend. Runs the real `fx` binary
 * through its documented noninteractive mode, `fx ask --json`, and continues
 * the same saved session with `--resume <session_id>` for repair and refusal
 * follow-ups.
 *
 * Read-only, like the Pi backend: each run gets a throwaway HOME whose
 * permission rules allow only read_file, glob_files and grep_files, inside
 * the project root, and deny every other tool; fx does not offer denied
 * tools to the model. web_fetch rules only match an exact `domain:<host>`,
 * so "*" can't deny it for every domain; web_fetch and web_search are moved
 * into toolbox instead, which "*" denies.
 * Verified against fx 0.0.17: the model is offered exactly read_file,
 * glob_files and grep_files.
 */
const FX_TOOL_PLACEMENT = { web_fetch: "toolbox", web_search: "toolbox" } as const;

export const FX_DEFAULT_MODEL = "openai/gpt-6.2-sol";
const DEFAULT_THINKING_LEVEL = "high";
const FX_EFFORTS = new Set(["minimal", "low", "medium", "high", "xhigh"]);
const CUSTOM_PROVIDER = "deepsec-custom";
/**
 * Path rules for the three read tools. fx matches a rule against the path
 * argument as the model sent it, so relative paths stay allowed and anything
 * that can leave the project root is denied: absolute paths, `~`, and any
 * `..` segment (a leading `..` needs its own pattern because `*` matches at
 * least one character). Verified against fx 0.0.17 with read_file, glob_files
 * and grep_files. Symlinks inside the repository are not resolved.
 */
const FX_PROJECT_PATHS_ONLY = {
  "*": "allow",
  "/*": "deny",
  "~*": "deny",
  "..*": "deny",
  "*..*": "deny",
} as const;

/** fx permission rule keys: read_file -> read, glob_files -> glob, grep_files -> grep. */
export const FX_READ_ONLY_PERMISSIONS = {
  "*": "deny",
  read: FX_PROJECT_PATHS_ONLY,
  glob: FX_PROJECT_PATHS_ONLY,
  grep: FX_PROJECT_PATHS_ONLY,
} as const;

const FX_SYSTEM_NOTE =
  "You are running as a read-only Deepsec backend. Use only the read_file, glob_files and grep_files tools, " +
  "stay inside the repository, and return the requested JSON.";

interface FxAgentConfig {
  model?: string;
  maxTurns?: number;
  thinkingLevel?: string;
  aiBaseUrl?: string;
  aiApiKeyEnv?: string;
}

interface FxAskJson {
  output?: string;
  final_output?: string;
  exit_code?: number;
  model?: string;
  session_id?: string;
  steps?: number;
  error?: string;
  usage?: {
    input_tokens?: number | null;
    output_tokens?: number | null;
    cache_read_tokens?: number | null;
    cache_write_tokens?: number | null;
  };
  tool_calls?: Array<{ name?: string; status?: string }>;
  recovery?: { state?: string; need?: string; message?: string };
}

interface FxPromptResult {
  resultText: string;
  meta: Partial<BatchMeta>;
  turnCount: number;
  toolUseCount: number;
}

function readConfig(config: Record<string, unknown>): FxAgentConfig {
  return {
    model: typeof config.model === "string" ? config.model : undefined,
    maxTurns: typeof config.maxTurns === "number" ? config.maxTurns : undefined,
    thinkingLevel: typeof config.thinkingLevel === "string" ? config.thinkingLevel : undefined,
    aiBaseUrl: typeof config.aiBaseUrl === "string" ? config.aiBaseUrl : undefined,
    aiApiKeyEnv: typeof config.aiApiKeyEnv === "string" ? config.aiApiKeyEnv : undefined,
  };
}

export function resolveFxEffort(thinkingLevel: string | undefined): string {
  const effort = thinkingLevel ?? DEFAULT_THINKING_LEVEL;
  if (!FX_EFFORTS.has(effort)) {
    throw new Error(
      `fx does not support thinking level "${effort}" (use ${[...FX_EFFORTS].join(", ")})`,
    );
  }
  return effort;
}

/** The fx settings written into the run's throwaway HOME. */
export function buildFxSettings(cfg: FxAgentConfig): Record<string, unknown> {
  const settings: Record<string, unknown> = {
    permission_mode: "ask",
    permission: FX_READ_ONLY_PERMISSIONS,
    tool_placement: FX_TOOL_PLACEMENT,
    // Titles are a separate helper-model request that would be billed to
    // the candidate under a different model.
    session_titles: false,
  };
  if (cfg.aiBaseUrl) {
    settings.providers = {
      [CUSTOM_PROVIDER]: {
        protocol: "openai-chat-completions",
        base_url: cfg.aiBaseUrl,
        auth: cfg.aiApiKeyEnv ? { type: "bearer", env: cfg.aiApiKeyEnv } : { type: "none" },
        model_metadata: {
          [cfg.model ?? FX_DEFAULT_MODEL]: {
            context_window: 200000,
            max_output_tokens: 32000,
            supports_tool_use: true,
          },
        },
      },
    };
  }
  return settings;
}

export function buildFxAskArgs(
  cfg: FxAgentConfig,
  options: { resumeSessionId?: string; maxTurns: number },
): string[] {
  const args = [
    "ask",
    "--json",
    "--ask",
    "--provider",
    cfg.aiBaseUrl ? CUSTOM_PROVIDER : "gateway",
    "--model",
    cfg.model ?? FX_DEFAULT_MODEL,
    "--effort",
    resolveFxEffort(cfg.thinkingLevel),
    "--config",
    `max_agent_steps=${options.maxTurns}`,
  ];
  if (options.resumeSessionId) args.push("--resume", options.resumeSessionId);
  return args;
}

function fxBinary(): string {
  return process.env.DEEPSEC_FX_BIN || "fx";
}

function fxEnvironment(home: string, cfg: FxAgentConfig): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    HOME: home,
    PATH: process.env.PATH,
    FX_AUTO_UPGRADE: "0",
    FX_DISABLE_KEYCHAIN: "1",
    FX_SOUND: "0",
    NO_COLOR: "1",
  };
  for (const key of [
    "AI_GATEWAY_API_KEY",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "SSL_CERT_FILE",
  ]) {
    if (process.env[key]) env[key] = process.env[key];
  }
  if (cfg.aiApiKeyEnv && process.env[cfg.aiApiKeyEnv])
    env[cfg.aiApiKeyEnv] = process.env[cfg.aiApiKeyEnv];
  return env;
}

/** Parses the single JSON object `fx ask --json` prints on stdout. */
export function parseFxAskOutput(stdout: string): FxAskJson {
  const text = stdout.trim();
  const start = text.indexOf("{");
  if (start < 0) throw new Error(`fx printed no JSON result: ${text.slice(0, 300)}`);
  return JSON.parse(text.slice(start)) as FxAskJson;
}

function errorMessage(result: FxAskJson | undefined, stderr: string, code: number | null): string {
  const parts = [
    result?.error,
    result?.recovery?.need ? `needs ${result.recovery.need}` : undefined,
    result?.recovery?.message,
    stderr.trim().split("\n").slice(-5).join("\n"),
  ].filter(Boolean);
  return `fx exited ${code ?? "by signal"}: ${parts.join(" | ") || "(no output)"}`;
}

/**
 * A failed `fx ask`. `turnIncomplete` is set when fx printed its JSON result
 * but the turn did not finish (a model error such as a provider safety-filter
 * block). Like an incomplete Codex turn, any output from it is progress, not
 * a result, so the batch is retried on a fresh session and never parsed.
 */
class FxAskError extends Error {
  constructor(
    message: string,
    readonly turnIncomplete: boolean,
  ) {
    super(message);
    this.name = "FxAskError";
  }
}

/** One saved fx conversation in its own HOME, continued across prompts. */
class FxSession {
  readonly home: string;
  sessionId?: string;

  constructor(
    readonly projectRoot: string,
    readonly cfg: FxAgentConfig,
  ) {
    this.home = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-fx-"));
    fs.mkdirSync(path.join(this.home, ".fx"), { mode: 0o700 });
    fs.writeFileSync(
      path.join(this.home, ".fx", "settings.json"),
      JSON.stringify(buildFxSettings(cfg), null, 2),
      { mode: 0o600 },
    );
  }

  get modelLabel(): string {
    return this.cfg.model ?? FX_DEFAULT_MODEL;
  }

  async ask(prompt: string, maxTurns: number, signal?: AbortSignal): Promise<FxAskJson> {
    const args = buildFxAskArgs(this.cfg, { resumeSessionId: this.sessionId, maxTurns });
    const child = spawn(fxBinary(), args, {
      cwd: this.projectRoot,
      env: fxEnvironment(this.home, this.cfg),
      stdio: ["pipe", "pipe", "pipe"],
      signal,
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (d) => {
      stdout += d;
    });
    child.stderr.setEncoding("utf8").on("data", (d) => {
      stderr += d;
    });
    child.stdin.end(prompt);
    const code = await new Promise<number | null>((resolve, reject) => {
      child.once("error", reject);
      child.once("close", resolve);
    });
    let result: FxAskJson | undefined;
    try {
      result = parseFxAskOutput(stdout);
    } catch {
      result = undefined;
    }
    if (code !== 0 || !result || result.exit_code !== 0) {
      throw new FxAskError(errorMessage(result, stderr, code), result !== undefined);
    }
    if (result.session_id) this.sessionId = result.session_id;
    return result;
  }

  dispose(): void {
    fs.rmSync(this.home, { recursive: true, force: true });
  }
}

function metaFromResult(result: FxAskJson, durationMs: number): Partial<BatchMeta> {
  const u = result.usage;
  return {
    durationMs,
    numTurns: result.steps,
    agentSessionId: result.session_id || undefined,
    usage: u
      ? {
          inputTokens: u.input_tokens ?? 0,
          outputTokens: u.output_tokens ?? 0,
          cacheReadInputTokens: u.cache_read_tokens ?? 0,
          cacheCreationInputTokens: u.cache_write_tokens ?? 0,
        }
      : undefined,
  };
}

async function runFxPrompt(
  session: FxSession,
  prompt: string,
  maxTurns: number,
  signal?: AbortSignal,
): Promise<FxPromptResult> {
  const startTime = Date.now();
  const result = await session.ask(`${FX_SYSTEM_NOTE}\n\n${prompt}`, maxTurns, signal);
  return {
    resultText: result.final_output || result.output || "",
    meta: metaFromResult(result, Date.now() - startTime),
    turnCount: result.steps ?? 0,
    toolUseCount: result.tool_calls?.length ?? 0,
  };
}

/** A follow-up in the same session. Read-only rules still apply; the prompt asks for no tools. */
async function runFollowUp(
  session: FxSession | undefined,
  prompt: string,
  signal?: AbortSignal,
): Promise<string | undefined> {
  if (!session?.sessionId) return undefined;
  try {
    const result = await session.ask(
      `Answer from what you already know. Do not call any tools.\n\n${prompt}`,
      8,
      signal,
    );
    return result.final_output || result.output || "";
  } catch {
    return undefined;
  }
}

async function runRefusalFollowUp(
  session: FxSession | undefined,
  signal?: AbortSignal,
): Promise<RefusalReport | undefined> {
  const raw = await runFollowUp(session, REFUSAL_FOLLOWUP_PROMPT, signal);
  return raw === undefined ? undefined : parseRefusalReport(raw);
}

/**
 * Runs the main prompt with Deepsec's retry policy. Every attempt starts a
 * fresh session. Transient errors and incomplete turns (see FxAskError) are
 * retried; after the last attempt the batch fails, so the processor marks its
 * files as errors and a later run picks them up again. Returns the live
 * session (for follow-ups) and the result; throws QuotaExhaustedError on
 * quota errors.
 */
async function* runWithRetries(
  projectRoot: string,
  cfg: FxAgentConfig,
  prompt: string,
  maxTurns: number,
  label: string,
  startedMessage: (model: string) => string,
  signal?: AbortSignal,
): AsyncGenerator<AgentProgress, { session: FxSession; run: FxPromptResult }> {
  let lastError = "";
  let attempts = 0;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    attempts = attempt;
    const session = new FxSession(projectRoot, cfg);
    if (attempt === 1) yield { type: "started", message: startedMessage(session.modelLabel) };
    else
      yield {
        type: "thinking",
        message: `Retrying fx ${label} on a fresh session (attempt ${attempt}/${MAX_ATTEMPTS}): ${lastError.slice(0, 200)}`,
      };
    let turnIncomplete = false;
    try {
      const run = await runFxPrompt(session, prompt, maxTurns, signal);
      if (run.resultText) return { session, run };
      lastError = "fx returned an empty response";
    } catch (err) {
      lastError = err instanceof Error ? err.message : String(err);
      turnIncomplete = err instanceof FxAskError && err.turnIncomplete;
      yield { type: "error", message: `fx error: ${lastError.slice(0, 300)}` };
    }
    session.dispose();
    if (signal?.aborted) {
      throw signal.reason instanceof Error ? signal.reason : new Error("fx batch aborted");
    }
    const quotaSource = classifyQuotaError(lastError);
    if (quotaSource) throw new QuotaExhaustedError(quotaSource, lastError);
    if (attempt >= MAX_ATTEMPTS) break;
    if (!turnIncomplete && !isTransientError(lastError)) break;
    await backoff(attempt);
  }
  throw new Error(
    `fx produced no ${label} result after ${attempts} attempt(s). Last error: ${lastError || "(none captured)"}.`,
  );
}

export async function runFxSetupTask(params: SetupTaskParams): Promise<string> {
  const cfg = readConfig(params.config);
  const session = new FxSession(params.projectRoot, cfg);
  try {
    params.onProgress?.({
      type: "started",
      message: `Understanding repository with fx (${session.modelLabel})`,
    });
    const run = await runFxPrompt(session, params.prompt, cfg.maxTurns ?? 40, params.signal);
    const text = run.resultText.trim();
    if (!text) throw new Error("fx produced no setup result");
    params.onProgress?.({ type: "complete", message: "Repository setup analysis complete" });
    return text;
  } finally {
    session.dispose();
  }
}

export class FxAgentPlugin implements AgentPlugin {
  type = "fx";

  async *investigate(params: InvestigateParams): AsyncGenerator<AgentProgress, InvestigateOutput> {
    const { batch, projectRoot, promptTemplate, projectInfo, config, signal, projectId } = params;
    const cfg = readConfig(config);
    const maxTurns = cfg.maxTurns ?? 150;
    const prompt = buildInvestigatePrompt({ promptTemplate, projectInfo, batch });
    const startTime = Date.now();
    const { session, run } = yield* runWithRetries(
      projectRoot,
      cfg,
      prompt,
      maxTurns,
      "investigation",
      (model) => `Investigating ${batch.length} file(s) with fx (${model})`,
      signal,
    );
    try {
      let resultText = run.resultText;
      const durationMs = Date.now() - startTime;
      let parsed: ParsedInvestigateResults;
      try {
        parsed = parseInvestigateResults(resultText, batch);
      } catch (err) {
        yield {
          type: "thinking",
          message: "fx returned non-JSON investigation output; requesting JSON-only repair",
        };
        const repairText = await runFollowUp(
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
          throw err;
        }
        try {
          parsed = parseInvestigateResults(repairText, batch);
          resultText = repairText;
          yield { type: "thinking", message: "fx JSON repair succeeded" };
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

      let results: InvestigateResult[] = parsed.results;
      if (parsed.invalid.length > 0) {
        const fieldRepair = yield* runInvestigateFieldRepairLoop({
          results,
          invalid: parsed.invalid,
          batch,
          followUp: (p) => runFollowUp(session, p, signal),
          agentLabel: "fx",
          agentType: this.type,
          projectId,
        });
        results = fieldRepair.results;
      }

      const refusal = await runRefusalFollowUp(session, signal);
      if (refusal?.refused) {
        yield { type: "thinking", message: `Refusal detected: ${refusal.reason ?? "see raw"}` };
      }
      const tokensStr = run.meta.usage
        ? ` ${run.meta.usage.inputTokens + run.meta.usage.outputTokens} tokens`
        : "";
      yield {
        type: "complete",
        message: `Investigation complete (${(durationMs / 1000).toFixed(1)}s, ${run.turnCount} turns, ${run.toolUseCount} tool calls${tokensStr}${refusal?.refused ? " refusal" : ""})`,
      };
      return { results, meta: { ...run.meta, durationMs, refusal } };
    } finally {
      session.dispose();
    }
  }

  async *revalidate(params: RevalidateParams): AsyncGenerator<AgentProgress, RevalidateOutput> {
    const {
      batch,
      projectRoot,
      projectInfo,
      config,
      force = false,
      onlyFindingIds,
      signal,
      projectId,
    } = params;
    const cfg = readConfig(config);
    const maxTurns = cfg.maxTurns ?? 150;
    const { prompt, totalFindings, expected } = buildRevalidatePrompt({
      batch,
      projectRoot,
      projectInfo,
      force,
      onlyFindingIds: onlyFindingIds ? new Set(onlyFindingIds) : undefined,
    });
    const startTime = Date.now();
    const { session, run } = yield* runWithRetries(
      projectRoot,
      cfg,
      prompt,
      maxTurns,
      "revalidation",
      (model) =>
        `Revalidating ${totalFindings} finding(s) across ${batch.length} file(s) with fx (${model})`,
      signal,
    );
    try {
      let resultText = run.resultText;
      const durationMs = Date.now() - startTime;
      const preResponses: RevalidateRawResponse[] = [];
      const jsonRepairPrompt = buildRevalidateJsonRepairPrompt(expected);
      let verdicts: RevalidateVerdict[];
      try {
        verdicts = parseRevalidateVerdicts(resultText);
      } catch (err) {
        yield {
          type: "thinking",
          message: "fx returned non-JSON revalidation output; requesting JSON-only repair",
        };
        const repairText = await runFollowUp(session, jsonRepairPrompt, signal);
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
          preResponses.push({ kind: "json-repair", prompt: jsonRepairPrompt, rawText: resultText });
          resultText = repairText;
          yield { type: "thinking", message: "fx JSON repair succeeded" };
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

      const repair = yield* runRevalidateIdRepairLoop({
        expected,
        verdicts,
        initialRawText: resultText,
        followUp: (p) => runFollowUp(session, p, signal),
        agentLabel: "fx",
      });
      verdicts = repair.verdicts;

      const refusal = await runRefusalFollowUp(session, signal);
      if (refusal?.refused) {
        yield {
          type: "thinking",
          message: `Refusal detected during revalidation: ${refusal.reason ?? "see raw"}`,
        };
      }
      yield {
        type: "complete",
        message: `Revalidation complete (${(durationMs / 1000).toFixed(1)}s, ${run.turnCount} turns, ${run.toolUseCount} tool calls, ${verdicts.length} verdicts${refusal?.refused ? " refusal" : ""})`,
      };
      return {
        verdicts,
        meta: { ...run.meta, durationMs, refusal },
        rawResponses: [...preResponses, ...repair.rawResponses],
        repairAttempts: repair.repairAttempts,
      };
    } finally {
      session.dispose();
    }
  }
}

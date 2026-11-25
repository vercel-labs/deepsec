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
  ContentFilteredError,
  classifyQuotaError,
  formatJsonRepairFailureDebugText,
  isContentFilterBlock,
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
 *
 * The path rules below are lexical. Symlinks are handled twice: fx resolves
 * the real path of every read, glob and grep target and refuses targets
 * outside the workspace ("Path is outside the workspace"), and the backend
 * refuses to start when a symlink in the project resolves outside it. The
 * opt-in test fx-cli-symlinks.test.ts checks fx's side against a real binary.
 */
const FX_TOOL_PLACEMENT = { web_fetch: "toolbox", web_search: "toolbox" } as const;

export const FX_DEFAULT_MODEL = "openai/gpt-6.2-sol";
const DEFAULT_THINKING_LEVEL = "xhigh";
const FX_EFFORTS = new Set(["minimal", "low", "medium", "high", "xhigh"]);
const CUSTOM_PROVIDER = "deepsec-custom";
/**
 * Path rules for the three read tools. fx matches a rule against the path
 * argument as the model sent it, so relative paths stay allowed and anything
 * that can leave the project root is denied: absolute paths, `~`, and any
 * `..` segment. fx's `*` also matches nothing, so the patterns cover a bare
 * `/`, `~` and `..` too. Verified against fx 0.0.17 with read_file, glob_files
 * and grep_files. Symlinks are covered separately (see the note above).
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
  /** Extra headers for a custom endpoint, with literal values. */
  aiHeaders?: Record<string, string>;
  /** Header that carries the custom endpoint's credential. */
  aiCredentialHeader?: { name: string; scheme: "bearer" | "raw" };
}

interface FxAskJson {
  output?: string;
  final_output?: string;
  exit_code?: number;
  model?: string;
  session_id?: string;
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
  toolUseCount: number;
}

function readConfig(config: Record<string, unknown>): FxAgentConfig {
  return {
    model: typeof config.model === "string" ? config.model : undefined,
    maxTurns: typeof config.maxTurns === "number" ? config.maxTurns : undefined,
    thinkingLevel: typeof config.thinkingLevel === "string" ? config.thinkingLevel : undefined,
    aiBaseUrl: typeof config.aiBaseUrl === "string" ? config.aiBaseUrl : undefined,
    aiApiKeyEnv: typeof config.aiApiKeyEnv === "string" ? config.aiApiKeyEnv : undefined,
    aiHeaders:
      config.aiHeaders && typeof config.aiHeaders === "object" && !Array.isArray(config.aiHeaders)
        ? (config.aiHeaders as Record<string, string>)
        : undefined,
    aiCredentialHeader:
      config.aiCredentialHeader && typeof config.aiCredentialHeader === "object"
        ? (config.aiCredentialHeader as { name: string; scheme: "bearer" | "raw" })
        : undefined,
  };
}

const FX_CREDENTIAL_ENV = "DEEPSEC_FX_CREDENTIAL";

/**
 * Headers for a custom endpoint, mapped onto fx's connection format: fx reads
 * every header value from an environment variable, so each literal value gets
 * a private variable in fx's environment. The credential goes in fx's bearer
 * auth when it is `Authorization: Bearer`, and in its own header otherwise.
 */
function customEndpointHeaders(cfg: FxAgentConfig): {
  auth: Record<string, unknown>;
  headers: Array<{ name: string; env: string; value?: string }>;
} {
  const headers = Object.entries(cfg.aiHeaders ?? {}).map(([name, value], i) => ({
    name,
    env: `DEEPSEC_FX_HEADER_${i}`,
    value,
  }));
  if (!cfg.aiApiKeyEnv) return { auth: { type: "none" }, headers };
  const credential = cfg.aiCredentialHeader;
  const isAuthorization = !credential || credential.name.toLowerCase() === "authorization";
  if (isAuthorization) {
    if (credential && credential.scheme !== "bearer") {
      throw new Error(
        "fx sends an Authorization credential only with the Bearer scheme; use a different credential header",
      );
    }
    return { auth: { type: "bearer", env: FX_CREDENTIAL_ENV }, headers };
  }
  if (credential.scheme === "raw") {
    return {
      auth: { type: "none" },
      headers: [...headers, { name: credential.name, env: FX_CREDENTIAL_ENV }],
    };
  }
  const key = process.env[cfg.aiApiKeyEnv];
  return {
    auth: { type: "none" },
    headers: [
      ...headers,
      { name: credential.name, env: FX_CREDENTIAL_ENV, value: key ? `Bearer ${key}` : undefined },
    ],
  };
}

function resolveFxEffort(thinkingLevel: string | undefined): string {
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
    const endpoint = customEndpointHeaders(cfg);
    settings.providers = {
      [CUSTOM_PROVIDER]: {
        protocol: "openai-chat-completions",
        base_url: cfg.aiBaseUrl,
        auth: endpoint.auth,
        ...(endpoint.headers.length > 0
          ? { headers: Object.fromEntries(endpoint.headers.map((h) => [h.name, { env: h.env }])) }
          : {}),
        model_metadata: {
          [cfg.model ?? FX_DEFAULT_MODEL]: {
            context_window: 200000,
            max_output_tokens: 32000,
            supports_tool_use: true,
            // fx drops an --effort its model metadata doesn't list.
            reasoning_efforts: Object.fromEntries(
              [...FX_EFFORTS].map((effort) => [effort, { reasoning_effort: effort }]),
            ),
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
  for (const key of ["HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "SSL_CERT_FILE"]) {
    if (process.env[key]) env[key] = process.env[key];
  }
  if (cfg.aiBaseUrl) {
    const key = cfg.aiApiKeyEnv && process.env[cfg.aiApiKeyEnv];
    if (key) env[FX_CREDENTIAL_ENV] = key;
    for (const header of customEndpointHeaders(cfg).headers) {
      if (header.value !== undefined) env[header.env] = header.value;
    }
  } else if (process.env.AI_GATEWAY_API_KEY) {
    env.AI_GATEWAY_API_KEY = process.env.AI_GATEWAY_API_KEY;
  }
  return env;
}

/** Parses the single JSON object `fx ask --json` prints on stdout. */
function parseFxAskOutput(stdout: string): FxAskJson {
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
 * Token usage of every `fx ask` in one batch: each attempt, including failed
 * ones, and every follow-up. fx's `input_tokens` includes cache reads and
 * writes; Deepsec's `inputTokens` counts uncached input only.
 */
class FxUsageLedger {
  private input = 0;
  private output = 0;
  private cacheRead = 0;
  private cacheWrite = 0;
  private reported = false;

  add(usage: FxAskJson["usage"]): void {
    if (!usage) return;
    for (const value of [usage.input_tokens, usage.output_tokens]) {
      if (typeof value === "number") this.reported = true;
    }
    this.input += usage.input_tokens ?? 0;
    this.output += usage.output_tokens ?? 0;
    this.cacheRead += usage.cache_read_tokens ?? 0;
    this.cacheWrite += usage.cache_write_tokens ?? 0;
  }

  usage(): BatchMeta["usage"] | undefined {
    if (!this.reported) return undefined;
    return {
      inputTokens: Math.max(0, this.input - this.cacheRead - this.cacheWrite),
      outputTokens: this.output,
      cacheReadInputTokens: this.cacheRead,
      cacheCreationInputTokens: this.cacheWrite,
    };
  }
}

const GATEWAY_MODELS_URL = "https://ai-gateway.vercel.sh/v1/models";

/** USD per token. */
interface FxTokenRates {
  input: number;
  output: number;
  cacheRead: number;
  cacheWrite: number;
}

/** Base per-token prices from AI Gateway's public model list. */
export function parseGatewayPricing(body: unknown): Map<string, FxTokenRates> {
  const rates = new Map<string, FxTokenRates>();
  const models = (body as { data?: unknown })?.data;
  if (!Array.isArray(models)) return rates;
  for (const model of models as Array<{ id?: unknown; pricing?: Record<string, unknown> }>) {
    const price = (key: string) => {
      const raw = model.pricing?.[key];
      if (typeof raw !== "number" && (typeof raw !== "string" || raw.trim() === ""))
        return undefined;
      const value = Number(raw);
      return Number.isFinite(value) && value >= 0 ? value : undefined;
    };
    const input = price("input");
    const output = price("output");
    if (typeof model.id !== "string" || input === undefined || output === undefined) continue;
    rates.set(model.id, {
      input,
      output,
      cacheRead: price("input_cache_read") ?? input,
      cacheWrite: price("input_cache_write") ?? input,
    });
  }
  return rates;
}

let gatewayPricing: Promise<Map<string, FxTokenRates> | undefined> | undefined;

function loadGatewayPricing(): Promise<Map<string, FxTokenRates> | undefined> {
  gatewayPricing ??= fetch(GATEWAY_MODELS_URL, { signal: AbortSignal.timeout(10_000) })
    .then((response) => (response.ok ? response.json() : undefined))
    .then((body) => (body === undefined ? undefined : parseGatewayPricing(body)))
    .catch(() => undefined);
  return gatewayPricing;
}

/** Test hook: forget the cached AI Gateway prices. */
export function resetFxPricingCache(): void {
  gatewayPricing = undefined;
}

/**
 * Estimated batch cost from AI Gateway's base prices, like the Codex
 * backend's estimate. Tiered long-context prices are not applied because fx
 * reports totals, not per-request counts. Undefined for custom endpoints or
 * when the price list is unavailable.
 */
async function estimateFxCostUsd(
  cfg: FxAgentConfig,
  usage: BatchMeta["usage"] | undefined,
): Promise<number | undefined> {
  if (cfg.aiBaseUrl || !usage) return undefined;
  const rates = (await loadGatewayPricing())?.get(cfg.model ?? FX_DEFAULT_MODEL);
  if (!rates) return undefined;
  return (
    usage.inputTokens * rates.input +
    usage.outputTokens * rates.output +
    usage.cacheReadInputTokens * rates.cacheRead +
    usage.cacheCreationInputTokens * rates.cacheWrite
  );
}

/**
 * Why a cost limit can't be enforced for fx with this model and endpoint,
 * or undefined when it can. Without a price every batch would count as $0
 * and the limit would never stop the run.
 */
export async function fxCostLimitError(
  model: string | undefined,
  aiBaseUrl: string | undefined,
): Promise<string | undefined> {
  const consequence =
    "so --max-cost-usd can't be enforced. Remove the limit or use a Gateway model with a listed price.";
  if (aiBaseUrl) return `fx can't price requests to a custom endpoint, ${consequence}`;
  const id = model ?? FX_DEFAULT_MODEL;
  if ((await loadGatewayPricing())?.has(id)) return undefined;
  return `AI Gateway's price list has no entry for ${id}, ${consequence}`;
}

/**
 * Project-relative paths of symlinks whose real target is outside the
 * project. Dangling links are skipped (nothing can be read through them),
 * and `.git` is not walked.
 */
export function findSymlinksOutsideProject(projectRoot: string, limit = 5): string[] {
  const root = fs.realpathSync.native(projectRoot);
  const escapes: string[] = [];
  const pending = [root];
  while (pending.length > 0 && escapes.length < limit) {
    const dir = pending.pop() as string;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) {
        let target: string;
        try {
          target = fs.realpathSync.native(full);
        } catch {
          continue;
        }
        if (target !== root && !target.startsWith(root + path.sep)) {
          escapes.push(path.relative(root, full));
          if (escapes.length >= limit) break;
        }
      } else if (entry.isDirectory() && entry.name !== ".git") {
        pending.push(full);
      }
    }
  }
  return escapes;
}

/** Projects this process has already found free of escaping symlinks. */
const projectsWithoutEscapes = new Set<string>();

/**
 * Second layer under fx's own workspace check: refuse to run on a project
 * whose symlinks resolve outside it. The walk covers the whole tree, so it
 * runs once per project per process rather than once per batch; fx still
 * checks the real path of every read, including links added later.
 */
function assertNoSymlinksOutsideProject(projectRoot: string): void {
  if (projectsWithoutEscapes.has(projectRoot)) return;
  const escapes = findSymlinksOutsideProject(projectRoot);
  if (escapes.length > 0) {
    throw new Error(
      `The fx backend refuses projects with symlinks that point outside the project root: ${escapes.join(", ")}. ` +
        "Remove or replace these links, or use another backend.",
    );
  }
  projectsWithoutEscapes.add(projectRoot);
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

/** A successful fx result without token counts; the batch's spend would be unknown. */
class FxUsageError extends Error {
  constructor() {
    super("fx --json output has no usage; this fx version is not supported");
    this.name = "FxUsageError";
  }
}

/** One saved fx conversation in its own HOME, continued across prompts. */
class FxSession {
  readonly home: string;
  sessionId?: string;

  constructor(
    readonly projectRoot: string,
    readonly cfg: FxAgentConfig,
    readonly ledger?: FxUsageLedger,
  ) {
    this.home = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-fx-"));
    try {
      fs.mkdirSync(path.join(this.home, ".fx"), { mode: 0o700 });
      fs.writeFileSync(
        path.join(this.home, ".fx", "settings.json"),
        JSON.stringify(buildFxSettings(cfg), null, 2),
        { mode: 0o600 },
      );
    } catch (err) {
      this.dispose();
      throw err;
    }
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
    // fx may exit before reading the whole prompt; its exit status reports why.
    child.stdin.on("error", () => {});
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
    this.ledger?.add(result?.usage);
    if (code !== 0 || !result || result.exit_code !== 0) {
      throw new FxAskError(errorMessage(result, stderr, code), result !== undefined);
    }
    // Cost limits depend on it; fx 0.0.17 and later always report token counts.
    if (
      typeof result.usage?.input_tokens !== "number" ||
      typeof result.usage.output_tokens !== "number"
    )
      throw new FxUsageError();
    if (result.session_id) this.sessionId = result.session_id;
    return result;
  }

  dispose(): void {
    fs.rmSync(this.home, { recursive: true, force: true });
  }
}

/** Usage and cost come from the batch's FxUsageLedger, not one result. */
function metaFromResult(result: FxAskJson): Partial<BatchMeta> {
  return {
    agentSessionId: result.session_id || undefined,
  };
}

async function runFxPrompt(
  session: FxSession,
  prompt: string,
  maxTurns: number,
  signal?: AbortSignal,
): Promise<FxPromptResult> {
  const result = await session.ask(`${FX_SYSTEM_NOTE}\n\n${prompt}`, maxTurns, signal);
  return {
    resultText: result.final_output || result.output || "",
    meta: metaFromResult(result),
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
  } catch (err) {
    // A follow-up is optional, but unknown spend, exhausted quota and
    // cancellation must still stop the run.
    if (err instanceof FxUsageError || signal?.aborted) throw err;
    const message = err instanceof Error ? err.message : String(err);
    const quotaSource = classifyQuotaError(message);
    if (quotaSource) throw new QuotaExhaustedError(quotaSource, message);
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
): AsyncGenerator<
  AgentProgress,
  { session: FxSession; run: FxPromptResult; ledger: FxUsageLedger }
> {
  assertNoSymlinksOutsideProject(projectRoot);
  const ledger = new FxUsageLedger();
  let lastError = "";
  let attempts = 0;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    attempts = attempt;
    const session = new FxSession(projectRoot, cfg, ledger);
    // Handed to the caller only on success; any other exit from this block,
    // including the consumer closing the generator at a yield, removes it.
    let handedOff = false;
    let turnIncomplete = false;
    try {
      if (attempt === 1) yield { type: "started", message: startedMessage(session.modelLabel) };
      else
        yield {
          type: "thinking",
          message: `Retrying fx ${label} on a fresh session (attempt ${attempt}/${MAX_ATTEMPTS}): ${lastError.slice(0, 200)}`,
        };
      try {
        const run = await runFxPrompt(session, prompt, maxTurns, signal);
        if (run.resultText) {
          handedOff = true;
          return { session, run, ledger };
        }
        lastError = "fx returned an empty response";
      } catch (err) {
        lastError = err instanceof Error ? err.message : String(err);
        turnIncomplete = err instanceof FxAskError && err.turnIncomplete;
        yield { type: "error", message: `fx error: ${lastError.slice(0, 300)}` };
        // A provider content filter ended the turn. Retrying the same batch
        // right away tends to hit the same filter; the processor pauses and
        // retries the files in smaller groups instead, as it does for Codex.
        if (isContentFilterBlock(lastError)) throw new ContentFilteredError(lastError);
      }
    } finally {
      if (!handedOff) session.dispose();
    }
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
  assertNoSymlinksOutsideProject(params.projectRoot);
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
    const { session, run, ledger } = yield* runWithRetries(
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
      const durationMs = Date.now() - startTime;
      const usage = ledger.usage();
      const costUsd = await estimateFxCostUsd(cfg, usage);
      const tokensStr = usage
        ? ` ${usage.inputTokens + usage.cacheReadInputTokens + usage.cacheCreationInputTokens + usage.outputTokens} tokens`
        : "";
      const costStr = costUsd !== undefined ? ` $${costUsd.toFixed(3)}` : "";
      yield {
        type: "complete",
        message: `Investigation complete (${(durationMs / 1000).toFixed(1)}s, ${run.toolUseCount} tool calls${costStr}${tokensStr}${refusal?.refused ? " refusal" : ""})`,
      };
      return { results, meta: { ...run.meta, usage, costUsd, durationMs, refusal } };
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
    const { session, run, ledger } = yield* runWithRetries(
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
      const durationMs = Date.now() - startTime;
      const usage = ledger.usage();
      const costUsd = await estimateFxCostUsd(cfg, usage);
      const costStr = costUsd !== undefined ? ` $${costUsd.toFixed(3)}` : "";
      yield {
        type: "complete",
        message: `Revalidation complete (${(durationMs / 1000).toFixed(1)}s, ${run.toolUseCount} tool calls${costStr}, ${verdicts.length} verdicts${refusal?.refused ? " refusal" : ""})`,
      };
      return {
        verdicts,
        meta: { ...run.meta, usage, costUsd, durationMs, refusal },
        rawResponses: [...preResponses, ...repair.rawResponses],
        repairAttempts: repair.repairAttempts,
      };
    } finally {
      session.dispose();
    }
  }
}

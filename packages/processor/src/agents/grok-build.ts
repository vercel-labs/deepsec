import { spawn } from "node:child_process";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
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

const DEFAULT_MODEL = "grok-4.6";
const DEFAULT_THINKING_LEVEL = "xhigh";

const INVESTIGATE_TOOLS = "read_file,grep,list_dir,run_terminal_cmd";
const SETUP_TOOLS = "read_file,grep,list_dir";
const TOOLLESS = "read_file";

const GROK_ENV_ALLOWLIST = new Set<string>([
  "PATH",
  "HOME",
  "USER",
  "LOGNAME",
  "SHELL",
  "TERM",
  "TZ",
  "LANG",
  "LANGUAGE",
  "LC_ALL",
  "LC_CTYPE",
  "LC_MESSAGES",
  "LC_COLLATE",
  "LC_NUMERIC",
  "LC_TIME",
  "TMPDIR",
  "TMP",
  "TEMP",
  "PWD",
  "GROK_HOME",
  "GROK_DISABLE_AUTOUPDATER",
  "GROK_SANDBOX",
  "RUST_LOG",
  "RUST_BACKTRACE",
]);

interface GrokJsonResult {
  text?: string;
  stopReason?: string;
  sessionId?: string;
  requestId?: string;
  num_turns?: number;
  total_cost_usd?: number;
  usage?: {
    input_tokens?: number;
    output_tokens?: number;
    cache_read_input_tokens?: number;
    cache_creation_input_tokens?: number;
    reasoning_tokens?: number;
    total_tokens?: number;
  };
  modelUsage?: Record<string, unknown>;
  type?: string;
  message?: string;
}

interface GrokRunResult {
  resultText: string;
  meta: Partial<BatchMeta>;
  raw: GrokJsonResult;
}

interface GrokRunOptions {
  prompt: string;
  projectRoot: string;
  model: string;
  maxTurns: number;
  tools: string;
  thinkingLevel: string;
  resumeSessionId?: string;
  signal?: AbortSignal;
  onProgress?: (progress: AgentProgress) => void;
  grokHome?: string;
  keepHome?: boolean;
}

function resolveThinkingLevel(config: Record<string, unknown>): string {
  const level = config.thinkingLevel ?? config.reasoningEffort;
  if (typeof level === "string" && level.length > 0) return level;
  return DEFAULT_THINKING_LEVEL;
}

function resolveGrokBinary(): string {
  if (process.env.GROK_EXECUTABLE) return process.env.GROK_EXECUTABLE;
  const candidates = [
    path.join(os.homedir(), ".local", "bin", "grok"),
    path.join(os.homedir(), ".grok", "bin", "grok"),
    "/opt/homebrew/bin/grok",
    "/usr/local/bin/grok",
  ];
  for (const c of candidates) {
    try {
      fs.accessSync(c, fs.constants.X_OK);
      return c;
    } catch {
      // try next
    }
  }
  return "grok";
}

export function makeIsolatedGrokHome(): string {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-grok-home-"));
  fs.writeFileSync(
    path.join(home, "config.toml"),
    ["[ui]", 'permission_mode = "dontAsk"', "", "[cli]", "auto_update = false", ""].join("\n"),
    { mode: 0o600 },
  );

  const userHomes = [process.env.GROK_HOME, path.join(os.homedir(), ".grok")].filter(
    (p): p is string => typeof p === "string" && p.length > 0,
  );

  for (const userHome of userHomes) {
    const auth = path.join(userHome, "auth.json");
    if (!fs.existsSync(auth)) continue;
    const dst = path.join(home, "auth.json");
    try {
      fs.symlinkSync(auth, dst);
    } catch {
      fs.copyFileSync(auth, dst);
      fs.chmodSync(dst, 0o600);
    }
    break;
  }

  return home;
}

export function buildGrokEnv(grokHome: string): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (typeof v !== "string") continue;
    if (GROK_ENV_ALLOWLIST.has(k) || k.startsWith("LC_")) {
      env[k] = v;
    }
  }
  env.GROK_HOME = grokHome;
  env.GROK_DISABLE_AUTOUPDATER = "1";
  for (const k of ["XAI_API_KEY", "XAI_API_BASE_URL"]) {
    const v = process.env[k];
    if (typeof v === "string") env[k] = v;
  }
  return env;
}

function sandboxProfile(): string {
  if (process.env.DEEPSEC_INSIDE_SANDBOX === "1") return "off";
  return process.env.DEEPSEC_GROK_SANDBOX ?? "read-only";
}

function extractJsonObject(text: string): string | undefined {
  const start = text.indexOf("{");
  if (start < 0) return undefined;
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (ch === "\\") {
        escaped = true;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }
    if (ch === '"') {
      inString = true;
      continue;
    }
    if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) return text.slice(start, i + 1);
    }
  }
  return undefined;
}

export function parseGrokStdout(stdout: string): GrokJsonResult {
  const trimmed = stdout.trim();
  if (!trimmed) throw new Error("Grok produced empty stdout");
  try {
    return JSON.parse(trimmed) as GrokJsonResult;
  } catch {
    const slice = extractJsonObject(trimmed);
    if (!slice) throw new Error(`Grok stdout was not JSON: ${trimmed.slice(0, 200)}`);
    return JSON.parse(slice) as GrokJsonResult;
  }
}

function metaFromGrokJson(raw: GrokJsonResult): Partial<BatchMeta> {
  const meta: Partial<BatchMeta> = {
    agentSessionId: raw.sessionId,
    numTurns: raw.num_turns,
  };
  if (typeof raw.total_cost_usd === "number") {
    meta.costUsd = raw.total_cost_usd;
  }
  if (raw.usage) {
    meta.usage = {
      inputTokens: raw.usage.input_tokens ?? 0,
      outputTokens: raw.usage.output_tokens ?? 0,
      cacheReadInputTokens: raw.usage.cache_read_input_tokens ?? 0,
      cacheCreationInputTokens: raw.usage.cache_creation_input_tokens ?? 0,
    };
  }
  return meta;
}

async function runGrokHeadless(opts: GrokRunOptions): Promise<GrokRunResult> {
  const bin = resolveGrokBinary();
  const grokHome = opts.grokHome ?? makeIsolatedGrokHome();
  const ownHome = opts.grokHome === undefined;
  const sandbox = sandboxProfile();

  const args = [
    "-p",
    opts.prompt,
    "--cwd",
    opts.projectRoot,
    "--output-format",
    "json",
    "--permission-mode",
    "dontAsk",
    "--tools",
    opts.tools,
    "--max-turns",
    String(opts.maxTurns),
    "-m",
    opts.model,
    "--reasoning-effort",
    opts.thinkingLevel,
    "--sandbox",
    sandbox,
    "--no-subagents",
    "--disable-web-search",
    "--no-memory",
    "--verbatim",
    "--disallowed-tools",
    "search_replace,write,image_gen,image_edit,image_to_video,reference_to_video,Agent",
  ];

  if (opts.resumeSessionId) {
    args.push("--resume", opts.resumeSessionId);
  }

  const env = buildGrokEnv(grokHome);
  let promptFile: string | undefined;
  if (Buffer.byteLength(opts.prompt, "utf8") > 80_000) {
    promptFile = path.join(
      os.tmpdir(),
      `deepsec-grok-prompt-${crypto.randomBytes(8).toString("hex")}.txt`,
    );
    fs.writeFileSync(promptFile, opts.prompt, { mode: 0o600 });
    const pIdx = args.indexOf("-p");
    if (pIdx >= 0) {
      args.splice(pIdx, 2, "--prompt-file", promptFile);
    }
  }

  opts.onProgress?.({
    type: "started",
    message: `Running Grok Build (${opts.model}, effort=${opts.thinkingLevel})`,
  });

  try {
    const { stdout, stderr, code } = await spawnCollect({
      bin,
      args,
      env,
      cwd: opts.projectRoot,
      signal: opts.signal,
    });

    if (code !== 0) {
      const errText = (stderr || stdout || `exit ${code}`).trim();
      const quota = classifyQuotaError(errText);
      if (quota) throw new QuotaExhaustedError(quota, errText);

      let structuredMsg: string | undefined;
      try {
        const errObj = parseGrokStdout(stdout);
        if (errObj.type === "error" || errObj.message) {
          structuredMsg = errObj.message ?? errText;
        }
      } catch {
        // ignore
      }
      const msg = structuredMsg ?? errText;
      const q = classifyQuotaError(msg);
      if (q) throw new QuotaExhaustedError(q, msg);
      throw new Error(`Grok exited ${code}: ${msg.slice(0, 500)}`);
    }

    const raw = parseGrokStdout(stdout);
    if (raw.type === "error") {
      const msg = raw.message ?? "unknown Grok error";
      const q = classifyQuotaError(msg);
      if (q) throw new QuotaExhaustedError(q, msg);
      throw new Error(`Grok error: ${msg}`);
    }

    const resultText = String(raw.text ?? "").trim();
    if (!resultText) {
      throw new Error(
        `Grok produced no result text (stopReason=${raw.stopReason ?? "?"}, turns=${raw.num_turns ?? "?"}).`,
      );
    }

    return {
      resultText,
      meta: metaFromGrokJson(raw),
      raw,
    };
  } finally {
    if (promptFile) {
      try {
        fs.unlinkSync(promptFile);
      } catch {
        // ignore
      }
    }
    if (ownHome && !opts.keepHome) {
      cleanupHome(grokHome);
    }
  }
}

function spawnCollect(params: {
  bin: string;
  args: string[];
  env: Record<string, string>;
  cwd: string;
  signal?: AbortSignal;
}): Promise<{ stdout: string; stderr: string; code: number | null }> {
  return new Promise((resolve, reject) => {
    if (params.signal?.aborted) {
      reject(new Error("Aborted before Grok spawn"));
      return;
    }

    const child = spawn(params.bin, params.args, {
      cwd: params.cwd,
      env: params.env,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    let killTimer: ReturnType<typeof setTimeout> | undefined;
    child.stdout?.setEncoding("utf8");
    child.stderr?.setEncoding("utf8");
    child.stdout?.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr?.on("data", (chunk: string) => {
      stderr += chunk;
    });

    const onAbort = () => {
      child.kill("SIGTERM");
      killTimer = setTimeout(() => {
        try {
          child.kill("SIGKILL");
        } catch {
          // ignore
        }
      }, 2_000);
      killTimer.unref?.();
    };
    params.signal?.addEventListener("abort", onAbort, { once: true });

    const finish = (fn: () => void) => {
      if (killTimer) clearTimeout(killTimer);
      params.signal?.removeEventListener("abort", onAbort);
      fn();
    };

    child.on("error", (err) => {
      finish(() => {
        if ((err as NodeJS.ErrnoException).code === "ENOENT") {
          reject(
            new Error(
              `Grok Build CLI not found (${params.bin}). Install Grok Build and ensure \`grok\` is on PATH, or set GROK_EXECUTABLE.`,
            ),
          );
          return;
        }
        reject(err);
      });
    });

    child.on("close", (code) => {
      finish(() => resolve({ stdout, stderr, code }));
    });
  });
}

async function runToollessFollowUp(params: {
  sessionId: string | undefined;
  grokHome: string;
  projectRoot: string;
  model: string;
  thinkingLevel: string;
  prompt: string;
  signal?: AbortSignal;
}): Promise<string | undefined> {
  if (!params.sessionId) return undefined;
  try {
    const run = await runGrokHeadless({
      prompt: params.prompt,
      projectRoot: params.projectRoot,
      model: params.model,
      maxTurns: 1,
      tools: TOOLLESS,
      thinkingLevel: "low",
      resumeSessionId: params.sessionId,
      signal: params.signal,
      grokHome: params.grokHome,
      keepHome: true,
    });
    return run.resultText;
  } catch {
    return undefined;
  }
}

export async function runGrokSetupTask(params: SetupTaskParams): Promise<string> {
  const model = (params.config.model as string) ?? DEFAULT_MODEL;
  const thinkingLevel = resolveThinkingLevel(params.config);
  params.onProgress?.({
    type: "started",
    message: `Understanding repository with Grok Build (${model})`,
  });
  const run = await runGrokHeadless({
    prompt: params.prompt,
    projectRoot: params.projectRoot,
    model,
    maxTurns: (params.config.maxTurns as number) ?? 40,
    tools: SETUP_TOOLS,
    thinkingLevel,
    signal: params.signal,
    onProgress: params.onProgress,
  });
  if (!run.resultText.trim()) throw new Error("Grok produced no setup result");
  params.onProgress?.({ type: "complete", message: "Repository setup analysis complete" });
  return run.resultText.trim();
}

export class GrokBuildAgentPlugin implements AgentPlugin {
  type = "grok";

  async *investigate(params: InvestigateParams): AsyncGenerator<AgentProgress, InvestigateOutput> {
    const { batch, projectRoot, promptTemplate, projectInfo, config, signal, projectId } = params;
    const model = (config.model as string) ?? DEFAULT_MODEL;
    const maxTurns = (config.maxTurns as number) ?? 150;
    const thinkingLevel = resolveThinkingLevel(config);
    const prompt = buildInvestigatePrompt({ promptTemplate, projectInfo, batch });
    const startTime = Date.now();

    let resultText = "";
    let lastError = "";
    let sdkMeta: Partial<BatchMeta> = {};
    let sessionId: string | undefined;
    let grokHome: string | undefined;
    let turnCount = 0;

    yield {
      type: "started",
      message: `Investigating ${batch.length} file(s) with Grok Build (${model})`,
    };

    try {
      for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        if (attempt > 1) {
          yield {
            type: "thinking",
            message: `Retrying Grok batch after transient error (attempt ${attempt}/${MAX_ATTEMPTS}): ${lastError.slice(0, 200)}`,
          };
          resultText = "";
          lastError = "";
          sdkMeta = {};
          sessionId = undefined;
          cleanupHome(grokHome);
          grokHome = undefined;
        }

        try {
          grokHome = makeIsolatedGrokHome();
          const run = await runGrokHeadless({
            prompt,
            projectRoot,
            model,
            maxTurns,
            tools: INVESTIGATE_TOOLS,
            thinkingLevel,
            signal,
            grokHome,
            keepHome: true,
          });
          resultText = run.resultText;
          sdkMeta = run.meta;
          sessionId = run.raw.sessionId;
          turnCount = run.raw.num_turns ?? 0;
        } catch (err) {
          lastError = err instanceof Error ? err.message : String(err);
          if (err instanceof QuotaExhaustedError) throw err;
          yield { type: "error", message: `Grok error: ${lastError.slice(0, 300)}` };
        }

        if (resultText) break;
        const quotaSource = classifyQuotaError(lastError);
        if (quotaSource) throw new QuotaExhaustedError(quotaSource, lastError);
        if (attempt >= MAX_ATTEMPTS || !isTransientError(lastError)) break;
        await backoff(attempt);
      }

      if (!resultText) {
        throw new Error(
          `Grok Build produced no investigation result after ${MAX_ATTEMPTS} attempt(s). ` +
            `Last error: ${lastError || "(none captured)"}.`,
        );
      }

      const durationMs = Date.now() - startTime;
      let parsed: ParsedInvestigateResults;
      try {
        parsed = parseInvestigateResults(resultText, batch);
      } catch (err) {
        yield {
          type: "thinking",
          message: "Grok returned non-JSON investigation output; requesting JSON-only repair",
        };
        const repairText = await runToollessFollowUp({
          sessionId,
          grokHome: grokHome!,
          projectRoot,
          model,
          thinkingLevel,
          prompt: buildInvestigateJsonRepairPrompt(batch),
          signal,
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
          parsed = parseInvestigateResults(repairText, batch);
          resultText = repairText;
          yield { type: "thinking", message: "Grok JSON repair succeeded" };
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
          followUp: (p) =>
            runToollessFollowUp({
              sessionId,
              grokHome: grokHome!,
              projectRoot,
              model,
              thinkingLevel,
              prompt: p,
              signal,
            }),
          agentLabel: "Grok",
          agentType: this.type,
          projectId,
        });
        results = fieldRepair.results;
      }

      let refusal: RefusalReport | undefined;
      const refusalRaw = await runToollessFollowUp({
        sessionId,
        grokHome: grokHome!,
        projectRoot,
        model,
        thinkingLevel,
        prompt: REFUSAL_FOLLOWUP_PROMPT,
        signal,
      });
      if (refusalRaw) refusal = parseRefusalReport(refusalRaw);
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
        message: `Investigation complete (${(durationMs / 1000).toFixed(1)}s, ${turnCount} turns${costStr}${tokensStr}${refusal?.refused ? " refusal" : ""})`,
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
      cleanupHome(grokHome);
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
    const model = (config.model as string) ?? DEFAULT_MODEL;
    const maxTurns = (config.maxTurns as number) ?? 150;
    const thinkingLevel = resolveThinkingLevel(config);

    const { prompt, totalFindings, expected } = buildRevalidatePrompt({
      batch,
      projectRoot,
      projectInfo,
      force,
      onlyFindingIds: onlyFindingIds ? new Set(onlyFindingIds) : undefined,
    });

    yield {
      type: "started",
      message: `Revalidating ${totalFindings} finding(s) across ${batch.length} file(s) with Grok Build (${model})`,
    };

    const startTime = Date.now();
    let resultText = "";
    let lastError = "";
    let sdkMeta: Partial<BatchMeta> = {};
    let sessionId: string | undefined;
    let grokHome: string | undefined;
    const rawResponses: RevalidateRawResponse[] = [];

    try {
      for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        if (attempt > 1) {
          yield {
            type: "thinking",
            message: `Retrying Grok revalidation after transient error (attempt ${attempt}/${MAX_ATTEMPTS}): ${lastError.slice(0, 200)}`,
          };
          resultText = "";
          lastError = "";
          sdkMeta = {};
          sessionId = undefined;
          cleanupHome(grokHome);
          grokHome = undefined;
        }

        try {
          grokHome = makeIsolatedGrokHome();
          const run = await runGrokHeadless({
            prompt,
            projectRoot,
            model,
            maxTurns,
            tools: INVESTIGATE_TOOLS,
            thinkingLevel,
            signal,
            grokHome,
            keepHome: true,
          });
          resultText = run.resultText;
          sdkMeta = run.meta;
          sessionId = run.raw.sessionId;
        } catch (err) {
          lastError = err instanceof Error ? err.message : String(err);
          if (err instanceof QuotaExhaustedError) throw err;
          yield { type: "error", message: `Grok error: ${lastError.slice(0, 300)}` };
        }

        if (resultText) break;
        const quotaSource = classifyQuotaError(lastError);
        if (quotaSource) throw new QuotaExhaustedError(quotaSource, lastError);
        if (attempt >= MAX_ATTEMPTS || !isTransientError(lastError)) break;
        await backoff(attempt);
      }

      if (!resultText) {
        throw new Error(
          `Grok Build produced no revalidation result after ${MAX_ATTEMPTS} attempt(s). ` +
            `Last error: ${lastError || "(none captured)"}.`,
        );
      }

      let verdicts: RevalidateVerdict[];
      try {
        verdicts = parseRevalidateVerdicts(resultText);
      } catch (err) {
        yield {
          type: "thinking",
          message: "Grok returned non-JSON revalidation output; requesting JSON-only repair",
        };
        const repairPrompt = buildRevalidateJsonRepairPrompt(expected);
        const repairText = await runToollessFollowUp({
          sessionId,
          grokHome: grokHome!,
          projectRoot,
          model,
          thinkingLevel,
          prompt: repairPrompt,
          signal,
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
        rawResponses.push({ kind: "json-repair", prompt: repairPrompt, rawText: repairText });
        try {
          verdicts = parseRevalidateVerdicts(repairText);
          resultText = repairText;
          yield { type: "thinking", message: "Grok revalidation JSON repair succeeded" };
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

      const idRepair = yield* runRevalidateIdRepairLoop({
        expected,
        verdicts,
        initialRawText: resultText,
        followUp: async (p) =>
          runToollessFollowUp({
            sessionId,
            grokHome: grokHome!,
            projectRoot,
            model,
            thinkingLevel,
            prompt: p,
            signal,
          }),
        agentLabel: "Grok",
      });

      const durationMs = Date.now() - startTime;
      const costStr = sdkMeta.costUsd != null ? ` $${sdkMeta.costUsd.toFixed(3)}` : "";
      yield {
        type: "complete",
        message: `Revalidation complete (${(durationMs / 1000).toFixed(1)}s, ${idRepair.verdicts.length} verdicts${costStr})`,
      };

      return {
        verdicts: idRepair.verdicts,
        meta: {
          durationMs,
          ...sdkMeta,
        },
        rawResponses: [...rawResponses, ...idRepair.rawResponses],
        repairAttempts: idRepair.repairAttempts,
      };
    } finally {
      cleanupHome(grokHome);
    }
  }
}

function cleanupHome(home: string | undefined): void {
  if (!home) return;
  try {
    fs.rmSync(home, { recursive: true, force: true });
  } catch {
    // ignore
  }
}

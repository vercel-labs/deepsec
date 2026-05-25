import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import type { RefusalReport } from "@deepsec/core";
import {
  backoff,
  buildInvestigatePrompt,
  buildRevalidatePrompt,
  classifyQuotaError,
  isTransientError,
  MAX_ATTEMPTS,
  parseInvestigateResults,
  parseRefusalReport,
  parseRevalidateVerdicts,
  QuotaExhaustedError,
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

const DEFAULT_MODEL = "composer-2.5";

/** Override path to the Cursor Agent CLI (`agent`). */
const CURSOR_AGENT_EXECUTABLE = process.env.CURSOR_AGENT_EXECUTABLE;

const CURSOR_ENV_ALLOWLIST = new Set<string>([
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
  "PWD",
  "TMPDIR",
  "TMP",
  "TEMP",
  "DEEPSEC_INSIDE_SANDBOX",
]);

function whichSync(bin: string): string | undefined {
  const pathEnv = process.env.PATH || "";
  const sep = process.platform === "win32" ? ";" : ":";
  for (const dir of pathEnv.split(sep)) {
    if (!dir) continue;
    const p = join(dir, bin);
    if (existsSync(p)) return p;
    if (process.platform === "win32") {
      if (existsSync(join(dir, `${bin}.exe`))) return join(dir, `${bin}.exe`);
      if (existsSync(join(dir, `${bin}.cmd`))) return join(dir, `${bin}.cmd`);
    }
  }
  return undefined;
}

function resolveCursorExecutable(): string {
  if (CURSOR_AGENT_EXECUTABLE) return CURSOR_AGENT_EXECUTABLE;
  return whichSync("agent") ?? "agent";
}

function buildCursorEnv(): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (typeof v !== "string") continue;
    if (CURSOR_ENV_ALLOWLIST.has(k) || k.startsWith("LC_")) env[k] = v;
  }
  const apiKey = process.env.CURSOR_API_KEY;
  if (typeof apiKey === "string") env.CURSOR_API_KEY = apiKey;
  return env;
}

interface CursorRunResult {
  resultText: string;
  meta: Partial<BatchMeta>;
  lastError: string;
  sessionId?: string;
}

type CursorNdjson = Record<string, unknown>;

function toolCallLabel(msg: CursorNdjson): string | undefined {
  const tc = msg.tool_call as Record<string, unknown> | undefined;
  if (!tc) return undefined;
  if ("readToolCall" in tc) {
    const path = (tc.readToolCall as { args?: { path?: string } })?.args?.path;
    return path ? `Read: ${path.split("/").slice(-3).join("/")}` : "Read";
  }
  if ("grepToolCall" in tc) return "Grep";
  if ("globToolCall" in tc) return "Glob";
  if ("shellToolCall" in tc) {
    const cmd = (tc.shellToolCall as { args?: { command?: string } })?.args?.command;
    return cmd ? `Shell: ${cmd.slice(0, 80)}` : "Shell";
  }
  return "tool";
}

function usageFromResult(msg: CursorNdjson): BatchMeta["usage"] | undefined {
  const usage = msg.usage as
    | {
        inputTokens?: number;
        outputTokens?: number;
        cacheReadTokens?: number;
        cacheWriteTokens?: number;
      }
    | undefined;
  if (!usage) return undefined;
  return {
    inputTokens: usage.inputTokens ?? 0,
    outputTokens: usage.outputTokens ?? 0,
    cacheReadInputTokens: usage.cacheReadTokens ?? 0,
    cacheCreationInputTokens: usage.cacheWriteTokens ?? 0,
  };
}

async function* runCursorAgent(params: {
  projectRoot: string;
  model: string;
  prompt: string;
  signal?: AbortSignal;
  /** Resume an existing Cursor agent session (for short follow-up prompts). */
  resumeSessionId?: string;
}): AsyncGenerator<AgentProgress, CursorRunResult> {
  const executable = resolveCursorExecutable();
  const args = [
    "-p",
    "--trust",
    "--force",
    "--workspace",
    params.projectRoot,
    "--output-format",
    "stream-json",
    "--model",
    params.model,
  ];
  if (params.resumeSessionId) {
    args.push("--resume", params.resumeSessionId);
  }
  if (process.env.DEEPSEC_INSIDE_SANDBOX === "1") {
    args.push("--sandbox", "disabled");
  }

  const child = spawn(executable, args, {
    cwd: params.projectRoot,
    env: buildCursorEnv(),
    stdio: ["pipe", "pipe", "pipe"],
  });

  let resultText = "";
  let lastError = "";
  let sessionId: string | undefined;
  const meta: Partial<BatchMeta> = {};
  let toolUseCount = 0;

  const abortHandler = () => {
    child.kill("SIGTERM");
  };
  if (params.signal) {
    if (params.signal.aborted) abortHandler();
    else params.signal.addEventListener("abort", abortHandler, { once: true });
  }

  child.stdin.write(params.prompt);
  child.stdin.end();

  let stderr = "";
  child.stderr.on("data", (chunk: Buffer) => {
    stderr += chunk.toString();
  });

  const lines: string[] = [];
  let buffer = "";

  await new Promise<void>((resolve, reject) => {
    child.stdout.on("data", (chunk: Buffer) => {
      buffer += chunk.toString();
      let idx: number;
      while ((idx = buffer.indexOf("\n")) !== -1) {
        const line = buffer.slice(0, idx).trim();
        buffer = buffer.slice(idx + 1);
        if (line) lines.push(line);
      }
    });
    child.on("error", (err) => reject(err));
    child.on("close", (code) => {
      if (buffer.trim()) lines.push(buffer.trim());
      if (code !== 0 && !resultText) {
        lastError = stderr.trim() || `Cursor agent exited with code ${code}`;
      }
      resolve();
    });
  });

  if (params.signal) {
    params.signal.removeEventListener("abort", abortHandler);
  }

  for (const line of lines) {
    let msg: CursorNdjson;
    try {
      msg = JSON.parse(line) as CursorNdjson;
    } catch {
      continue;
    }

    switch (msg.type) {
      case "system":
        if (msg.subtype === "init") {
          sessionId = msg.session_id as string | undefined;
        }
        break;

      case "tool_call":
        if (msg.subtype === "started") {
          toolUseCount++;
          const label = toolCallLabel(msg);
          if (label) {
            yield { type: "tool_use", message: label };
          }
        }
        break;

      case "result":
        if (msg.subtype === "success" && !msg.is_error) {
          resultText = String(msg.result ?? "");
          meta.durationApiMs = msg.duration_api_ms as number | undefined;
          meta.agentSessionId = (msg.session_id as string) ?? sessionId;
          meta.usage = usageFromResult(msg);
        } else {
          lastError = String(msg.result ?? msg.error ?? "unknown");
          yield {
            type: "error",
            message: `Agent error: ${lastError.slice(0, 300)}`,
          };
        }
        break;
    }
  }

  if (!resultText && stderr && !lastError) {
    lastError = stderr.slice(0, 500);
  }

  return { resultText, meta, lastError, sessionId };
}

async function runRefusalFollowUp(
  sessionId: string | undefined,
  model: string,
  projectRoot: string,
): Promise<RefusalReport | undefined> {
  if (!sessionId) return undefined;
  try {
    const gen = runCursorAgent({
      projectRoot,
      model,
      prompt: REFUSAL_FOLLOWUP_PROMPT,
      resumeSessionId: sessionId,
    });
    let step = await gen.next();
    while (!step.done) step = await gen.next();
    return parseRefusalReport(step.value.resultText);
  } catch {
    return undefined;
  }
}

export class CursorCliPlugin implements AgentPlugin {
  type = "cursor";

  async *investigate(params: InvestigateParams): AsyncGenerator<AgentProgress, InvestigateOutput> {
    const { batch, projectRoot, promptTemplate, projectInfo, config, signal } = params;
    const model = (config.model as string) ?? DEFAULT_MODEL;

    yield {
      type: "started",
      message: `Investigating ${batch.length} file(s) with Cursor Agent CLI (${model})`,
    };

    const prompt = buildInvestigatePrompt({ promptTemplate, projectInfo, batch });
    const startTime = Date.now();
    let toolUseCount = 0;

    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      if (attempt > 1) {
        yield {
          type: "thinking",
          message: `Retrying batch (attempt ${attempt}/${MAX_ATTEMPTS})`,
        };
      }

      const gen = runCursorAgent({
        projectRoot,
        model,
        prompt,
        signal,
      });
      let step = await gen.next();
      while (!step.done) {
        if (step.value.type === "tool_use") toolUseCount++;
        yield step.value;
        step = await gen.next();
      }
      const run = step.value;

      if (run.resultText) {
        const durationMs = Date.now() - startTime;
        const refusal = await runRefusalFollowUp(run.sessionId, model, projectRoot);
        if (refusal?.refused) {
          yield {
            type: "thinking",
            message: `Refusal detected: ${refusal.reason ?? "see raw"}`,
          };
        }

        const tokensStr = run.meta.usage
          ? ` ${run.meta.usage.inputTokens + run.meta.usage.outputTokens} tokens`
          : "";
        yield {
          type: "complete",
          message: `Investigation complete (${(durationMs / 1000).toFixed(1)}s, ${toolUseCount} tool calls${tokensStr}${refusal?.refused ? " ⚠️  refusal" : ""})`,
        };

        return {
          results: parseInvestigateResults(run.resultText, batch),
          meta: {
            durationMs,
            ...run.meta,
            refusal,
          },
        };
      }

      const lastError = run.lastError;
      yield {
        type: "error",
        message: `Agent error: ${lastError.slice(0, 300)}`,
      };

      const quotaSource = classifyQuotaError(lastError);
      if (quotaSource) throw new QuotaExhaustedError(quotaSource, lastError);
      if (attempt >= MAX_ATTEMPTS || !isTransientError(lastError)) break;
      await backoff(attempt);
    }

    throw new Error(
      `Cursor Agent CLI produced no result after ${MAX_ATTEMPTS} attempt(s). ` +
        `Ensure \`agent\` is on PATH (Cursor CLI) or set CURSOR_AGENT_EXECUTABLE.`,
    );
  }

  async *revalidate(params: RevalidateParams): AsyncGenerator<AgentProgress, RevalidateOutput> {
    const { batch, projectRoot, projectInfo, config, force = false, signal } = params;
    const model = (config.model as string) ?? DEFAULT_MODEL;

    const { prompt, totalFindings } = buildRevalidatePrompt({
      batch,
      projectRoot,
      projectInfo,
      force,
    });

    yield {
      type: "started",
      message: `Revalidating ${totalFindings} finding(s) across ${batch.length} file(s) with Cursor Agent CLI (${model})`,
    };

    const startTime = Date.now();
    let toolUseCount = 0;

    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      if (attempt > 1) {
        yield {
          type: "thinking",
          message: `Retrying batch (attempt ${attempt}/${MAX_ATTEMPTS})`,
        };
      }

      const gen = runCursorAgent({
        projectRoot,
        model,
        prompt,
        signal,
      });
      let step = await gen.next();
      while (!step.done) {
        if (step.value.type === "tool_use") toolUseCount++;
        yield step.value;
        step = await gen.next();
      }
      const run = step.value;

      if (run.resultText) {
        const durationMs = Date.now() - startTime;
        yield {
          type: "complete",
          message: `Revalidation complete (${(durationMs / 1000).toFixed(1)}s, ${toolUseCount} tool calls)`,
        };
        return {
          verdicts: parseRevalidateVerdicts(run.resultText),
          meta: { durationMs, ...run.meta },
        };
      }

      const lastError = run.lastError;
      yield {
        type: "error",
        message: `Agent error: ${lastError.slice(0, 300)}`,
      };

      const quotaSource = classifyQuotaError(lastError);
      if (quotaSource) throw new QuotaExhaustedError(quotaSource, lastError);
      if (attempt >= MAX_ATTEMPTS || !isTransientError(lastError)) break;
      await backoff(attempt);
    }

    throw new Error(
      `Cursor Agent CLI produced no result after ${MAX_ATTEMPTS} attempt(s). ` +
        `Ensure \`agent\` is on PATH (Cursor CLI) or set CURSOR_AGENT_EXECUTABLE.`,
    );
  }
}

import { type ChildProcess, spawn } from "node:child_process";
import {
  buildInvestigatePrompt,
  buildRevalidatePrompt,
  classifyQuotaError,
  parseInvestigateResults,
  parseRevalidateVerdicts,
  QuotaExhaustedError,
} from "./shared.js";
import type {
  AgentPlugin,
  AgentProgress,
  InvestigateOutput,
  InvestigateParams,
  RevalidateOutput,
  RevalidateParams,
} from "./types.js";

const DEFAULT_MODEL = "gpt-5.5";
const DEFAULT_EFFORT = "xhigh";
const DEFAULT_TIMEOUT_MS = 900_000;
const DEFAULT_DELEGATE_COMMAND = "/Users/greenapple/.agents/scripts/copilot-delegate";
const DEFAULT_ROTATE_COMMAND = "/Users/greenapple/.agents/scripts/copilot-rotate";

const ENV_ALLOWLIST = new Set([
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
  "COPILOT_ROTATE_COOLDOWN",
  "COPILOT_ROTATE_STATE_DIR",
  "COPILOT_ROTATE_KEEP_SESSION",
]);

interface CopilotConfig {
  model: string;
  effort: string;
  timeoutMs: number;
  command: string;
  useDelegate: boolean;
}

interface CopilotRunResult {
  stdout: string;
  stderr: string;
  durationMs: number;
  agentSessionId?: string;
  numTurns?: number;
}

function resolveConfig(config: Record<string, unknown>): CopilotConfig {
  const useDelegate = config.useDelegate !== false;
  return {
    model: typeof config.model === "string" ? config.model : DEFAULT_MODEL,
    effort: typeof config.effort === "string" ? config.effort : DEFAULT_EFFORT,
    timeoutMs: typeof config.timeoutMs === "number" ? config.timeoutMs : DEFAULT_TIMEOUT_MS,
    command:
      typeof config.command === "string"
        ? config.command
        : useDelegate
          ? DEFAULT_DELEGATE_COMMAND
          : DEFAULT_ROTATE_COMMAND,
    useDelegate,
  };
}

function buildMinimalEnv(projectRoot: string, config: CopilotConfig): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (typeof value !== "string") continue;
    if (ENV_ALLOWLIST.has(key) || key.startsWith("LC_")) env[key] = value;
  }
  env.PWD = projectRoot;
  env.COPILOT_DELEGATE_TIMEOUT = String(Math.ceil(config.timeoutMs / 1000));
  return env;
}

function copilotPreamble(projectRoot: string): string {
  return `## Copilot delegation requirements

You are running as DeepSec's \`copilot-rotate\` backend inside GitHub Copilot CLI.

- Work from project root: \`${projectRoot}\`.
- Perform static analysis only. Do not run target services, exploit code, or make network requests.
- Read and trace the relevant source files before deciding.
- Your final answer MUST contain exactly one fenced \`\`\`json block matching the DeepSec schema below.
- Do not include any second JSON block. DeepSec will fail the batch if the JSON is malformed.

`;
}

function buildArgs(config: CopilotConfig, projectRoot: string, prompt: string): string[] {
  if (config.useDelegate) {
    return ["worker", config.model, config.effort, projectRoot, prompt];
  }
  return [
    "delegate",
    "--role",
    "worker",
    "--model",
    config.model,
    "--effort",
    config.effort,
    "--timeout-ms",
    String(config.timeoutMs),
    "--prompt",
    prompt,
  ];
}

function extractMeta(
  stdout: string,
  stderr: string,
): Pick<CopilotRunResult, "agentSessionId" | "numTurns"> {
  const combined = `${stdout}\n${stderr}`;
  const sessionMatch = combined.match(
    /\b(?:session|agentSessionId|session_id)[:=]\s*([A-Za-z0-9._:-]+)/i,
  );
  const turnsMatch = combined.match(/\b(?:numTurns|turns|num_turns)[:=]\s*(\d+)/i);
  return {
    agentSessionId: sessionMatch?.[1],
    numTurns: turnsMatch ? Number(turnsMatch[1]) : undefined,
  };
}

function finishChild(child: ChildProcess, reason: string): void {
  if (child.killed || child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  setTimeout(() => {
    if (!child.killed && child.exitCode === null && child.signalCode === null) {
      child.kill("SIGKILL");
    }
  }, 5_000).unref();
  child.stderr?.emit("data", `\n[deepsec] terminated copilot child: ${reason}\n`);
}

async function* runCopilot(
  purpose: "investigation" | "revalidation",
  projectRoot: string,
  prompt: string,
  config: CopilotConfig,
  signal?: AbortSignal,
): AsyncGenerator<AgentProgress, CopilotRunResult> {
  const args = buildArgs(config, projectRoot, prompt);
  const startTime = Date.now();
  let stdout = "";
  let stderr = "";
  let settled = false;
  let lastStderrLine = "";

  const child = spawn(config.command, args, {
    cwd: projectRoot,
    env: buildMinimalEnv(projectRoot, config),
    stdio: ["ignore", "pipe", "pipe"],
  });

  child.stdout.setEncoding("utf-8");
  child.stderr.setEncoding("utf-8");
  child.stdout.on("data", (chunk: string) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk: string) => {
    stderr += chunk;
    const lines = chunk.split(/\r?\n/).filter(Boolean);
    lastStderrLine = lines.at(-1) ?? lastStderrLine;
  });

  const timeout = setTimeout(() => {
    finishChild(child, `timeout after ${config.timeoutMs}ms`);
  }, config.timeoutMs);

  const abort = () => finishChild(child, "abort signal");
  if (signal) {
    if (signal.aborted) abort();
    else signal.addEventListener("abort", abort, { once: true });
  }

  const done = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => {
    child.on("error", (err) => {
      stderr += `\n${err instanceof Error ? err.message : String(err)}`;
      resolve({ code: -1, signal: null });
    });
    child.on("close", (code, childSignal) => resolve({ code, signal: childSignal }));
  });

  while (!settled) {
    const winner = await Promise.race([
      done.then((result) => ({ type: "done" as const, result })),
      new Promise<{ type: "tick" }>((resolve) =>
        setTimeout(() => resolve({ type: "tick" }), 15_000),
      ),
    ]);

    if (winner.type === "tick") {
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(0);
      yield {
        type: lastStderrLine ? "tool_use" : "thinking",
        message: lastStderrLine
          ? `Copilot ${purpose} running (${elapsed}s): ${lastStderrLine.slice(0, 200)}`
          : `Copilot ${purpose} running (${elapsed}s)`,
      };
      continue;
    }

    settled = true;
    clearTimeout(timeout);
    if (signal) signal.removeEventListener("abort", abort);

    const { code, signal: childSignal } = winner.result;
    const durationMs = Date.now() - startTime;
    if (code !== 0) {
      const errorText = stderr || stdout || `process exited with ${childSignal ?? code}`;
      const quotaSource = classifyQuotaError(errorText, "codex");
      if (quotaSource) throw new QuotaExhaustedError(quotaSource, errorText);
      throw new Error(
        `copilot-rotate ${purpose} failed with ${childSignal ?? `exit code ${code}`}: ${errorText.slice(0, 1200)}`,
      );
    }

    return {
      stdout,
      stderr,
      durationMs,
      ...extractMeta(stdout, stderr),
    };
  }

  throw new Error(`copilot-rotate ${purpose} ended unexpectedly`);
}

export class CopilotRotatePlugin implements AgentPlugin {
  type = "copilot-rotate";

  async *investigate(params: InvestigateParams): AsyncGenerator<AgentProgress, InvestigateOutput> {
    const { batch, projectRoot, promptTemplate, projectInfo, config, signal } = params;
    const copilotConfig = resolveConfig(config);
    yield {
      type: "started",
      message: `Investigating ${batch.length} file(s) with Copilot Rotate (${copilotConfig.model}, ${copilotConfig.effort})`,
    };

    const prompt =
      copilotPreamble(projectRoot) +
      buildInvestigatePrompt({
        promptTemplate,
        projectInfo,
        batch,
      });
    let run: CopilotRunResult;
    let results: InvestigateOutput["results"];
    try {
      run = yield* runCopilot("investigation", projectRoot, prompt, copilotConfig, signal);
      results = parseInvestigateResults(run.stdout, batch);
    } catch (err) {
      yield {
        type: "error",
        message:
          `Copilot investigation failed: ${err instanceof Error ? err.message : String(err)}`.slice(
            0,
            500,
          ),
      };
      throw err;
    }

    yield {
      type: "complete",
      message: `Copilot investigation complete (${(run.durationMs / 1000).toFixed(1)}s)`,
    };

    return {
      results,
      meta: {
        durationMs: run.durationMs,
        agentSessionId: run.agentSessionId,
        numTurns: run.numTurns,
      },
    };
  }

  async *revalidate(params: RevalidateParams): AsyncGenerator<AgentProgress, RevalidateOutput> {
    const { batch, projectRoot, projectInfo, config, force = false, signal } = params;
    const copilotConfig = resolveConfig(config);
    const { prompt, totalFindings } = buildRevalidatePrompt({
      batch,
      projectRoot,
      projectInfo,
      force,
    });

    yield {
      type: "started",
      message: `Revalidating ${totalFindings} finding(s) with Copilot Rotate (${copilotConfig.model}, ${copilotConfig.effort})`,
    };

    let run: CopilotRunResult;
    let verdicts: RevalidateOutput["verdicts"];
    try {
      run = yield* runCopilot(
        "revalidation",
        projectRoot,
        copilotPreamble(projectRoot) + prompt,
        copilotConfig,
        signal,
      );
      verdicts = parseRevalidateVerdicts(run.stdout);
    } catch (err) {
      yield {
        type: "error",
        message:
          `Copilot revalidation failed: ${err instanceof Error ? err.message : String(err)}`.slice(
            0,
            500,
          ),
      };
      throw err;
    }

    yield {
      type: "complete",
      message: `Copilot revalidation complete (${(run.durationMs / 1000).toFixed(1)}s)`,
    };

    return {
      verdicts,
      meta: {
        durationMs: run.durationMs,
        agentSessionId: run.agentSessionId,
        numTurns: run.numTurns,
      },
    };
  }
}

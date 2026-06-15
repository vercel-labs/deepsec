import type { RefusalReport } from "@deepsec/core";
import {
  Agent,
  CursorAgentError,
  type SDKAgent,
  type SDKMessage,
  type SDKToolUseMessage,
} from "@cursor/sdk";
import {
  backoff,
  buildInvestigatePrompt,
  buildRevalidatePrompt,
  isTransientError,
  MAX_ATTEMPTS,
  parseInvestigateResults,
  parseRefusalReport,
  parseRevalidateVerdicts,
  QuotaExhaustedError,
  REFUSAL_FOLLOWUP_PROMPT,
  writeParseFailureDebug,
} from "./shared.js";
import {
  buildCursorReadOnlyPreamble,
  DEFAULT_CURSOR_MODEL,
  resolveCursorModelSelection,
} from "./cursor-model.js";
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

const DEFAULT_MODEL = DEFAULT_CURSOR_MODEL;
const READONLY_MODE = "plan";

function trimForProgress(text: string, max = 200): string {
  const normalized = text.replace(/\s+/g, " ").trim();
  if (normalized.length <= max) return normalized;
  return `${normalized.slice(0, max - 1)}...`;
}

function extractToolTarget(args: unknown): string | undefined {
  if (!args || typeof args !== "object") return undefined;
  const record = args as Record<string, unknown>;
  for (const key of [
    "path",
    "filePath",
    "file_path",
    "pattern",
    "command",
    "query",
    "url",
    "glob_pattern",
    "target_notebook",
  ]) {
    const value = record[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return undefined;
}

function shortTarget(target: string | undefined): string | undefined {
  if (!target) return undefined;
  if (target.includes("\n")) return trimForProgress(target, 120);
  if (!target.includes("/")) return trimForProgress(target, 120);
  return target.split("/").slice(-3).join("/");
}

function classifyCursorQuotaError(message: string): boolean {
  const lower = message.toLowerCase();
  return (
    /\bquota\b/.test(lower) ||
    /\busage limit\b/.test(lower) ||
    /\bout of credits?\b/.test(lower) ||
    /\bbilling\b/.test(lower)
  );
}

function buildCursorAgentOptions(projectRoot: string, model: { id: string; params?: { id: string; value: string }[] }) {
  if (process.env.DEEPSEC_INSIDE_SANDBOX === "1") {
    throw new Error(
      "The built-in cursor provider currently supports local runs only. `deepsec sandbox ... --agent cursor` is not supported yet.",
    );
  }
  return {
    apiKey: process.env.CURSOR_API_KEY,
    model,
    mode: READONLY_MODE,
    local: {
      cwd: projectRoot,
    },
  } as const;
}

function renderToolMessage(message: SDKToolUseMessage): string {
  const target = shortTarget(extractToolTarget(message.args));
  const suffix = message.status === "running" ? "" : ` (${message.status})`;
  return `${message.name}${target ? `: ${target}` : ""}${suffix}`;
}

async function disposeAgent(agent: SDKAgent | undefined): Promise<void> {
  if (!agent) return;
  try {
    await agent[Symbol.asyncDispose]();
  } catch {
    try {
      agent.close();
    } catch {}
  }
}

async function runRefusalFollowUp(
  agent: SDKAgent,
  model: { id: string; params?: { id: string; value: string }[] },
): Promise<RefusalReport | undefined> {
  try {
    const run = await agent.send(REFUSAL_FOLLOWUP_PROMPT, {
      model,
      mode: READONLY_MODE,
    });
    const result = await run.wait();
    if (result.status !== "finished" || !result.result) return undefined;
    return parseRefusalReport(result.result);
  } catch {
    return undefined;
  }
}

interface CursorRunOutput {
  resultText: string;
  refusal?: RefusalReport;
  meta: Partial<BatchMeta>;
  durationMs: number;
  turnCount: number;
  toolUseCount: number;
}

async function* runCursorPrompt(params: {
  prompt: string;
  projectRoot: string;
  model: string;
  retryLabel: string;
}): AsyncGenerator<AgentProgress, CursorRunOutput> {
  const { prompt, projectRoot, model, retryLabel } = params;
  const startTime = Date.now();
  const resolvedModel = await resolveCursorModelSelection(model, {
    apiKey: process.env.CURSOR_API_KEY,
  });
  let resultText = "";
  let refusal: RefusalReport | undefined;
  let meta: Partial<BatchMeta> = {};
  let turnCount = 0;
  let toolUseCount = 0;
  let lastError = "";
  let retryable = false;

  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    if (attempt > 1) {
      yield {
        type: "thinking",
        message: `Retrying ${retryLabel} after transient error (attempt ${attempt}/${MAX_ATTEMPTS}): ${lastError.slice(0, 200)}`,
      };
      resultText = "";
      refusal = undefined;
      meta = {};
      turnCount = 0;
      toolUseCount = 0;
      lastError = "";
      retryable = false;
    }

    let agent: SDKAgent | undefined;

    try {
      agent = await Agent.create(buildCursorAgentOptions(projectRoot, resolvedModel));
      const run = await agent.send(prompt, {
        model: resolvedModel,
        mode: READONLY_MODE,
      });

      for await (const message of run.stream()) {
        const sdkMessage = message as SDKMessage;
        switch (sdkMessage.type) {
          case "assistant": {
            turnCount++;
            const text = sdkMessage.message.content
              .filter((block) => block.type === "text")
              .map((block) => block.text)
              .join(" ");
            if (text.trim()) {
              yield {
                type: "thinking",
                message: trimForProgress(text),
              };
            }
            break;
          }
          case "tool_call":
            toolUseCount++;
            yield {
              type: "tool_use",
              message: renderToolMessage(sdkMessage),
              candidateFile: extractToolTarget(sdkMessage.args),
            };
            break;
          case "thinking":
            yield {
              type: "thinking",
              message: trimForProgress(sdkMessage.text),
            };
            break;
          case "status":
            if (sdkMessage.message) {
              yield {
                type: sdkMessage.status === "ERROR" ? "error" : "thinking",
                message: trimForProgress(sdkMessage.message),
              };
            }
            break;
          case "task":
            if (sdkMessage.text) {
              yield {
                type: "thinking",
                message: trimForProgress(sdkMessage.text),
              };
            }
            break;
        }
      }

      const final = await run.wait();
      if (final.status !== "finished" || !final.result) {
        lastError = final.result?.trim() || `Cursor run ${final.status}`;
        yield {
          type: "error",
          message: `Cursor run ${final.status}: ${lastError.slice(0, 300)}`,
        };
      } else {
        resultText = final.result;
        meta = {
          durationApiMs: final.durationMs,
          numTurns: turnCount,
          agentSessionId: agent.agentId,
        };
        refusal = await runRefusalFollowUp(agent, resolvedModel);
      }
    } catch (err) {
      lastError = err instanceof Error ? err.message : String(err);
      if (classifyCursorQuotaError(lastError)) {
        throw new QuotaExhaustedError("cursor-quota", lastError);
      }
      retryable = err instanceof CursorAgentError ? err.isRetryable : isTransientError(lastError);
      yield {
        type: "error",
        message: `Cursor SDK error: ${lastError.slice(0, 300)}`,
      };
    } finally {
      await disposeAgent(agent);
    }

    if (resultText) break;
    if (classifyCursorQuotaError(lastError)) {
      throw new QuotaExhaustedError("cursor-quota", lastError);
    }
    if (attempt >= MAX_ATTEMPTS || !retryable) break;
    await backoff(attempt);
  }

  if (!resultText) {
    throw new Error(
      `Cursor SDK produced no result after ${MAX_ATTEMPTS} attempt(s). Last error: ${lastError || "(none captured)"}.`,
    );
  }

  return {
    resultText,
    refusal,
    meta,
    durationMs: Date.now() - startTime,
    turnCount,
    toolUseCount,
  };
}

export class CursorAgentSdkPlugin implements AgentPlugin {
  type = "cursor";

  async *investigate(params: InvestigateParams): AsyncGenerator<AgentProgress, InvestigateOutput> {
    const { batch, projectRoot, promptTemplate, projectInfo, config, projectId } = params;
    const model = (config.model as string) ?? DEFAULT_MODEL;

    yield {
      type: "started",
      message: `Investigating ${batch.length} file(s) with Cursor SDK (${model})`,
    };

    const prompt = `${buildCursorReadOnlyPreamble(projectRoot)}\n\n${buildInvestigatePrompt({
      promptTemplate,
      projectInfo,
      batch,
    })}`;
    const run = yield* runCursorPrompt({
      prompt,
      projectRoot,
      model,
      retryLabel: "investigation batch",
    });

    if (run.refusal?.refused) {
      yield {
        type: "thinking",
        message: `Refusal detected: ${run.refusal.reason ?? run.refusal.skipped?.map((s) => s.filePath ?? "?").join(", ") ?? "see raw"}`,
      };
    }

    let results: InvestigateResult[];
    try {
      results = parseInvestigateResults(run.resultText, batch);
    } catch (err) {
      writeParseFailureDebug({
        projectId,
        phase: "investigate",
        agentType: this.type,
        resultText: run.resultText,
        error: err,
        batch,
      });
      throw err;
    }

    yield {
      type: "complete",
      message: `Investigation complete (${(run.durationMs / 1000).toFixed(1)}s, ${run.turnCount} turns, ${run.toolUseCount} tool calls${run.refusal?.refused ? " refusal" : ""})`,
    };

    return {
      results,
      meta: {
        durationMs: run.durationMs,
        ...run.meta,
        refusal: run.refusal,
      },
    };
  }

  async *revalidate(params: RevalidateParams): AsyncGenerator<AgentProgress, RevalidateOutput> {
    const { batch, projectRoot, projectInfo, config, force = false, projectId } = params;
    const model = (config.model as string) ?? DEFAULT_MODEL;
    const { prompt, totalFindings } = buildRevalidatePrompt({
      batch,
      projectRoot,
      projectInfo,
      force,
    });

    yield {
      type: "started",
      message: `Revalidating ${totalFindings} finding(s) across ${batch.length} file(s) with Cursor SDK (${model})`,
    };

    const run = yield* runCursorPrompt({
      prompt: `${buildCursorReadOnlyPreamble(projectRoot)}\n\n${prompt}`,
      projectRoot,
      model,
      retryLabel: "revalidation batch",
    });

    if (run.refusal?.refused) {
      yield {
        type: "thinking",
        message: `Refusal detected during revalidation: ${run.refusal.reason ?? "see raw"}`,
      };
    }

    let verdicts: RevalidateVerdict[];
    try {
      verdicts = parseRevalidateVerdicts(run.resultText);
    } catch (err) {
      writeParseFailureDebug({
        projectId,
        phase: "revalidate",
        agentType: this.type,
        resultText: run.resultText,
        error: err,
        batch,
      });
      throw err;
    }

    yield {
      type: "complete",
      message: `Revalidation complete (${(run.durationMs / 1000).toFixed(1)}s, ${run.turnCount} turns, ${verdicts.length} verdicts${run.refusal?.refused ? " refusal" : ""})`,
    };

    return {
      verdicts,
      meta: {
        durationMs: run.durationMs,
        ...run.meta,
        refusal: run.refusal,
      },
    };
  }
}

import { query } from "@anthropic-ai/claude-agent-sdk";
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

async function runRefusalFollowUp(
  sessionId: string | undefined,
  model: string,
  projectRoot: string,
): Promise<RefusalReport | undefined> {
  if (!sessionId) return undefined;

  let raw = "";
  try {
    for await (const message of query({
      prompt: REFUSAL_FOLLOWUP_PROMPT,
      options: {
        cwd: projectRoot,
        allowedTools: [],
        permissionMode: "dontAsk",
        maxTurns: 1,
        model,
        resume: sessionId,
        thinking: { type: "adaptive" },
        effort: "low",
      },
    })) {
      const msg = message as Record<string, any>;
      if (msg.type === "result" && msg.subtype === "success") {
        raw = String(msg.result ?? "");
      }
    }
  } catch {
    return undefined;
  }

  return parseRefusalReport(raw);
}

export class ClaudeAgentSdkPlugin implements AgentPlugin {
  type = "claude-agent-sdk";

  async *investigate(params: InvestigateParams): AsyncGenerator<AgentProgress, InvestigateOutput> {
    const { batch, projectRoot, promptTemplate, projectInfo, config } = params;
    const model = (config.model as string) ?? "claude-opus-4-7";
    const maxTurns = (config.maxTurns as number) ?? 150;

    yield {
      type: "started",
      message: `Investigating ${batch.length} file(s) with Claude Agent SDK (${model})`,
    };

    const prompt = buildInvestigatePrompt({ promptTemplate, projectInfo, batch });
    const startTime = Date.now();
    let sessionId: string | undefined;
    let resultText = "";
    let turnCount = 0;
    let toolUseCount = 0;
    let sdkMeta: Partial<BatchMeta> = {};
    let lastError = "";
    let hadErrors = false;

    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      if (attempt > 1) {
        yield {
          type: "thinking" as const,
          message: `Retrying batch after transient error (attempt ${attempt}/${MAX_ATTEMPTS}): ${lastError.slice(0, 200)}`,
        };
        sessionId = undefined;
        resultText = "";
        turnCount = 0;
        toolUseCount = 0;
        sdkMeta = {};
        lastError = "";
        hadErrors = false;
      }

      try {
        for await (const message of query({
          prompt,
          options: {
            cwd: projectRoot,
            allowedTools: ["Read", "Glob", "Grep", "Bash"],
            permissionMode: "dontAsk",
            maxTurns,
            model,
            thinking: { type: "adaptive" },
            effort: "max",
          },
        })) {
          try {
            const msg = message as Record<string, any>;

            switch (msg.type) {
              case "system":
                if (msg.subtype === "init") {
                  sessionId = msg.session_id;
                }
                break;

              case "assistant": {
                turnCount++;
                const elapsed = ((Date.now() - startTime) / 1000).toFixed(0);
                const toolUses =
                  msg.message?.content?.filter((b: any) => b.type === "tool_use") ?? [];
                for (const tu of toolUses) {
                  toolUseCount++;
                  const input = tu.input ?? {};
                  const target = input.file_path || input.pattern || input.command || "";
                  const short =
                    typeof target === "string" ? target.split("/").slice(-3).join("/") : "";
                  yield {
                    type: "tool_use" as const,
                    message: `${tu.name}${short ? `: ${short}` : ""}`,
                    candidateFile: typeof target === "string" ? target : undefined,
                  };
                }
                if (toolUses.length === 0) {
                  yield {
                    type: "thinking" as const,
                    message: `Turn ${turnCount} (${elapsed}s, ${toolUseCount} tool calls)`,
                  };
                }
                break;
              }

              case "tool_progress":
                yield {
                  type: "tool_use" as const,
                  message: `${msg.tool_name} (${msg.elapsed_time_seconds?.toFixed(0) ?? "?"}s)`,
                };
                break;

              case "tool_use_summary":
                yield {
                  type: "thinking" as const,
                  message: msg.summary,
                };
                break;

              case "result":
                if (msg.subtype === "success") {
                  resultText = msg.result;
                  sdkMeta = {
                    durationApiMs: msg.duration_api_ms,
                    numTurns: msg.num_turns,
                    costUsd: msg.total_cost_usd,
                    agentSessionId: msg.session_id,
                  };
                  if (msg.usage) {
                    sdkMeta.usage = {
                      inputTokens: msg.usage.input_tokens ?? 0,
                      outputTokens: msg.usage.output_tokens ?? 0,
                      cacheReadInputTokens: msg.usage.cache_read_input_tokens ?? 0,
                      cacheCreationInputTokens: msg.usage.cache_creation_input_tokens ?? 0,
                    };
                  }
                } else {
                  lastError = String(msg.error ?? "unknown");
                  hadErrors = true;
                  yield {
                    type: "error" as const,
                    message: `Agent error: ${lastError.slice(0, 300)}`,
                  };
                }
                break;
            }
          } catch (msgErr) {
            yield {
              type: "error" as const,
              message: `Error processing SDK message: ${msgErr instanceof Error ? msgErr.message : String(msgErr)}`,
            };
          }
        }
      } catch (sdkErr) {
        lastError = sdkErr instanceof Error ? sdkErr.message : String(sdkErr);
        hadErrors = true;
        yield {
          type: "error" as const,
          message: `Agent SDK error: ${lastError.slice(0, 300)}`,
        };
      }

      if (resultText) break;
      if (attempt >= MAX_ATTEMPTS || !isTransientError(lastError)) break;
      await backoff(attempt);
    }

    const durationMs = Date.now() - startTime;
    const costStr = sdkMeta.costUsd != null ? ` $${sdkMeta.costUsd.toFixed(3)}` : "";
    const tokensStr = sdkMeta.usage
      ? ` ${sdkMeta.usage.inputTokens + sdkMeta.usage.outputTokens} tokens`
      : "";

    const refusal = await runRefusalFollowUp(sessionId, model, projectRoot);
    if (refusal?.refused) {
      yield {
        type: "thinking" as const,
        message: `Refusal detected: ${refusal.reason ?? refusal.skipped?.map((s) => s.filePath ?? "?").join(", ") ?? "see raw"}`,
      };
    }

    yield {
      type: "complete",
      message: `Investigation complete (${(durationMs / 1000).toFixed(1)}s, ${turnCount} turns, ${toolUseCount} tool calls${costStr}${tokensStr}${refusal?.refused ? " ⚠️  refusal" : ""})`,
    };

    return {
      results: parseInvestigateResults(resultText, batch),
      meta: {
        durationMs,
        ...sdkMeta,
        refusal,
        hadErrors,
      },
    };
  }

  async *revalidate(params: RevalidateParams): AsyncGenerator<AgentProgress, RevalidateOutput> {
    const { batch, projectRoot, projectInfo, config, force = false } = params;
    const model = (config.model as string) ?? "claude-opus-4-7";
    const maxTurns = (config.maxTurns as number) ?? 150;

    const { prompt, totalFindings } = buildRevalidatePrompt({
      batch,
      projectRoot,
      projectInfo,
      force,
    });

    yield {
      type: "started",
      message: `Revalidating ${totalFindings} finding(s) across ${batch.length} file(s)`,
    };

    const startTime = Date.now();
    let resultText = "";
    let sdkMeta: Partial<BatchMeta> = {};
    let turnCount = 0;
    let lastError = "";

    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      if (attempt > 1) {
        yield {
          type: "thinking" as const,
          message: `Retrying revalidation batch after transient error (attempt ${attempt}/${MAX_ATTEMPTS}): ${lastError.slice(0, 200)}`,
        };
        resultText = "";
        sdkMeta = {};
        turnCount = 0;
        lastError = "";
      }

      try {
        for await (const message of query({
          prompt,
          options: {
            cwd: projectRoot,
            allowedTools: ["Read", "Glob", "Grep", "Bash"],
            permissionMode: "dontAsk",
            maxTurns,
            model,
            thinking: { type: "adaptive" },
            effort: "max",
          },
        })) {
          try {
            const msg = message as Record<string, any>;
            if (msg.type === "assistant") {
              turnCount++;
              const toolUses =
                msg.message?.content?.filter((b: any) => b.type === "tool_use") ?? [];
              for (const tu of toolUses) {
                const input = tu.input ?? {};
                const target = input.file_path || input.pattern || "";
                const short =
                  typeof target === "string" ? target.split("/").slice(-3).join("/") : "";
                yield {
                  type: "tool_use" as const,
                  message: `${tu.name}${short ? `: ${short}` : ""}`,
                };
              }
            }
            if (msg.type === "result") {
              if (msg.subtype === "success") {
                resultText = msg.result;
                sdkMeta = {
                  durationApiMs: msg.duration_api_ms,
                  numTurns: msg.num_turns,
                  costUsd: msg.total_cost_usd,
                  agentSessionId: msg.session_id,
                };
                if (msg.usage) {
                  sdkMeta.usage = {
                    inputTokens: msg.usage.input_tokens ?? 0,
                    outputTokens: msg.usage.output_tokens ?? 0,
                    cacheReadInputTokens: msg.usage.cache_read_input_tokens ?? 0,
                    cacheCreationInputTokens: msg.usage.cache_creation_input_tokens ?? 0,
                  };
                }
              } else {
                lastError = String(msg.error ?? "unknown");
                yield {
                  type: "error" as const,
                  message: `Revalidate agent error: ${lastError.slice(0, 300)}`,
                };
              }
            }
          } catch {}
        }
      } catch (err) {
        lastError = err instanceof Error ? err.message : String(err);
        yield { type: "error" as const, message: `SDK error: ${lastError.slice(0, 300)}` };
      }

      if (resultText) break;
      if (attempt >= MAX_ATTEMPTS || !isTransientError(lastError)) break;
      await backoff(attempt);
    }

    const durationMs = Date.now() - startTime;
    const verdicts = parseRevalidateVerdicts(resultText);

    const refusal = await runRefusalFollowUp(sdkMeta.agentSessionId, model, projectRoot);
    if (refusal?.refused) {
      yield {
        type: "thinking" as const,
        message: `Refusal detected during revalidation: ${refusal.reason ?? "see raw"}`,
      };
    }

    const costStr = sdkMeta.costUsd != null ? ` $${sdkMeta.costUsd.toFixed(3)}` : "";
    yield {
      type: "complete",
      message: `Revalidation complete (${(durationMs / 1000).toFixed(1)}s, ${turnCount} turns${costStr}, ${verdicts.length} verdicts${refusal?.refused ? " ⚠️  refusal" : ""})`,
    };

    return {
      verdicts,
      meta: { durationMs, ...sdkMeta, refusal },
    };
  }
}

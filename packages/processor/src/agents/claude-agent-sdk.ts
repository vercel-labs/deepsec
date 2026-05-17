import { query, type SandboxSettings } from "@anthropic-ai/claude-agent-sdk";
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

/**
 * Optional path to the Claude Code native binary. The SDK normally
 * resolves this from its bundled platform-specific optional
 * dependencies, but pnpm sometimes ships incomplete content for
 * platform variants it didn't fetch (the Linux-x64-musl shell exists
 * but its `claude` binary is absent). Setting this env var lets CI
 * point at a separately-installed `@anthropic-ai/claude-code` and
 * sidestep the resolution path entirely.
 */
function claudeCodeExecutable(): string | undefined {
  return process.env.CLAUDE_CODE_EXECUTABLE;
}

/**
 * Variables the Claude Code CLI / spawned shell legitimately needs.
 * Same defense as the codex allowlist: prompt-injection via repository
 * content cannot ask the agent to `cat /proc/self/environ` and read
 * GITHUB_TOKEN, AWS_*, etc. when none of those reach the spawn env.
 *
 * The Claude SDK's `query()` accepts an `env` option that REPLACES
 * process.env in the spawned `claude` child. We construct a minimal
 * environment from this allowlist plus the credentials Claude actually
 * needs to authenticate.
 */
const CLAUDE_ENV_ALLOWLIST = new Set<string>([
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
  "DEBUG_CLAUDE_AGENT_SDK",
  "CLAUDE_CODE_ENTRYPOINT",
  "CLAUDE_CODE_DEBUG_LOGS_DIR",
]);

/**
 * Sandbox settings for the local run. The Claude Agent SDK can wrap the
 * spawned `claude` CLI in an OS-level sandbox (bubblewrap on Linux,
 * sandbox-exec/Seatbelt on macOS) so the agent's Bash tool can't escape
 * the host process — defense in depth on top of `permissionMode:
 * "dontAsk"` and the `allowedTools` allowlist.
 *
 * - In-VM (DEEPSEC_INSIDE_SANDBOX=1): no nested sandbox. The Vercel
 *   Sandbox microVM is the real boundary, and a nested OS sandbox just
 *   adds failure modes.
 * - Local: enable, auto-allow Bash without prompting, and degrade
 *   gracefully if the OS sandbox dependency is missing instead of
 *   hard-failing the run (`failIfUnavailable: false`). No filesystem or
 *   network restrictions are layered on top — the agent already only
 *   gets Read/Glob/Grep/Bash and `permissionMode: "dontAsk"` keeps
 *   everything quiet.
 */
function buildSandbox(): SandboxSettings | undefined {
  if (process.env.DEEPSEC_INSIDE_SANDBOX === "1") return undefined;
  return {
    enabled: true,
    autoAllowBashIfSandboxed: true,
    failIfUnavailable: false,
  };
}

/**
 * Build the minimal env passed to the Claude Code child process.
 * Allowlist + the credential routing the SDK was about to read off
 * `process.env` itself. Anything else (CI tokens, cloud creds, custom
 * vars) is dropped.
 */
function buildClaudeEnv(): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (typeof v !== "string") continue;
    if (CLAUDE_ENV_ALLOWLIST.has(k) || k.startsWith("LC_")) {
      env[k] = v;
    }
  }
  // Forward only the credential routing pair the SDK needs to auth.
  // ANTHROPIC_AUTH_TOKEN + ANTHROPIC_BASE_URL is the gateway pair;
  // ANTHROPIC_API_KEY covers direct-Anthropic. CLAUDE_CODE_OAUTH_TOKEN
  // is the subscription-mode token. Forwarding only these (rather
  // than wholesale process.env) means the agent's Bash sees just
  // these specific values — no GITHUB_TOKEN, AWS_*, etc.
  for (const k of [
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_BASE_URL",
    "CLAUDE_CODE_OAUTH_TOKEN",
  ]) {
    const v = process.env[k];
    if (typeof v === "string") env[k] = v;
  }
  return env;
}

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
        ...(claudeCodeExecutable() ? { pathToClaudeCodeExecutable: claudeCodeExecutable() } : {}),
        env: buildClaudeEnv(),
        sandbox: buildSandbox(),
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
    const { batch, projectRoot, promptTemplate, projectInfo, config, signal } = params;
    const model = (config.model as string) ?? "claude-opus-4-7";
    const maxTurns = (config.maxTurns as number) ?? 150;
    // Bridge the processor-supplied AbortSignal to an AbortController the
    // SDK can consume — the SDK API takes an `AbortController` instance,
    // not a raw signal. The processor aborts the parent signal when one
    // batch trips a `QuotaExhaustedError`, and that propagation cancels the
    // in-flight HTTP request mid-stream rather than us waiting for the next
    // polled message.
    const abortController = new AbortController();
    if (signal) {
      if (signal.aborted) abortController.abort();
      else signal.addEventListener("abort", () => abortController.abort(), { once: true });
    }

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
            ...(claudeCodeExecutable()
              ? { pathToClaudeCodeExecutable: claudeCodeExecutable() }
              : {}),
            env: buildClaudeEnv(),
            sandbox: buildSandbox(),
            abortController,
          },
        })) {
          const msg = message as Record<string, any>;

          // Structured quota signal — defined as a tagged enum in the
          // SDK's own type definitions: `SDKAssistantMessageError =
          // 'authentication_failed' | 'billing_error' | 'rate_limit'
          // | 'invalid_request' | 'server_error' | 'unknown'
          // | 'max_output_tokens'`. Both `SDKAssistantMessage` and
          // `SDKAssistantMessageErrorMessage` carry it. When present,
          // it's a definitive classification — no prose guessing — so we
          // trust it ahead of `classifyQuotaError`. Hoisted ABOVE the
          // inner per-message try/catch on purpose: that catch swallows
          // exceptions to keep the message loop going on transient
          // parsing glitches; a billing_error must escape.
          if (msg.error === "billing_error") {
            throw new QuotaExhaustedError(
              "anthropic-credits",
              `SDK error tag: billing_error${
                Array.isArray(msg.errors) && msg.errors.length
                  ? ` — ${String(msg.errors[0]).slice(0, 200)}`
                  : ""
              }`,
            );
          }

          try {
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
        yield {
          type: "error" as const,
          message: `Agent SDK error: ${lastError.slice(0, 300)}`,
        };
      }

      if (resultText) break;
      // Quota beats every other classification — a 429 here is "wallet
      // empty," and retrying just hits the same wall. Throw immediately so
      // the processor can abort other in-flight batches.
      const quotaSource = classifyQuotaError(lastError, "claude");
      if (quotaSource) {
        throw new QuotaExhaustedError(quotaSource, lastError);
      }
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

    // Hard-fail when the SDK never produced a result. Without this throw
    // the empty resultText falls through to `parseInvestigateResults` →
    // `[{filePath, findings: []}, …]`, which the processor accepts as a
    // clean "ran fine, found nothing" run. That silently masks fatal
    // errors like "claude binary not found" in CI.
    if (!resultText) {
      throw new Error(
        `Claude Agent SDK produced no result after ${MAX_ATTEMPTS} attempt(s). ` +
          `Last error: ${lastError || "(none captured)"}.`,
      );
    }

    return {
      results: parseInvestigateResults(resultText, batch),
      meta: {
        durationMs,
        ...sdkMeta,
        refusal,
      },
    };
  }

  async *revalidate(params: RevalidateParams): AsyncGenerator<AgentProgress, RevalidateOutput> {
    const { batch, projectRoot, projectInfo, config, force = false, signal } = params;
    const model = (config.model as string) ?? "claude-opus-4-7";
    const maxTurns = (config.maxTurns as number) ?? 150;

    // See investigate() — bridges processor's abort signal into the SDK's
    // expected AbortController shape.
    const abortController = new AbortController();
    if (signal) {
      if (signal.aborted) abortController.abort();
      else signal.addEventListener("abort", () => abortController.abort(), { once: true });
    }

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
            ...(claudeCodeExecutable()
              ? { pathToClaudeCodeExecutable: claudeCodeExecutable() }
              : {}),
            env: buildClaudeEnv(),
            sandbox: buildSandbox(),
            abortController,
          },
        })) {
          const msg = message as Record<string, any>;
          // Same structured billing_error short-circuit as investigate().
          if (msg.error === "billing_error") {
            throw new QuotaExhaustedError(
              "anthropic-credits",
              `SDK error tag: billing_error${
                Array.isArray(msg.errors) && msg.errors.length
                  ? ` — ${String(msg.errors[0]).slice(0, 200)}`
                  : ""
              }`,
            );
          }
          try {
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
      const quotaSource = classifyQuotaError(lastError, "claude");
      if (quotaSource) {
        throw new QuotaExhaustedError(quotaSource, lastError);
      }
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

    if (!resultText) {
      throw new Error(
        `Claude Agent SDK produced no revalidation result after ${MAX_ATTEMPTS} attempt(s). ` +
          `Last error: ${lastError || "(none captured)"}.`,
      );
    }

    return {
      verdicts,
      meta: { durationMs, ...sdkMeta, refusal },
    };
  }
}

import { spawn } from "node:child_process";
import {
  buildInvestigateJsonRepairPrompt,
  buildInvestigatePrompt,
  buildRevalidateJsonRepairPrompt,
  buildRevalidatePrompt,
  classifyQuotaError,
  formatJsonRepairFailureDebugText,
  jsonRepairFailureError,
  type ParsedInvestigateResults,
  parseInvestigateResults,
  parseRevalidateVerdicts,
  QuotaExhaustedError,
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

/**
 * Cursor CLI agent plugin.
 *
 * Unlike claude-agent-sdk / codex (which talk to a model endpoint over
 * HTTP), this backend drives the **Cursor CLI** (`cursor-agent`) headless.
 * Cursor's own agent runs the tool-use loop (Read / Glob / Shell) against
 * the checkout and prints newline-delimited JSON events; we parse those
 * into deepsec's AgentProgress stream and pull the final findings JSON out
 * of the assistant text.
 *
 * Why a CLI backend and not the HTTP path: the Cursor "seat" (Ratatoskr
 * bridge) exposes an OpenAI/Anthropic-compatible *message* API but does NOT
 * relay agentic `tool_use`, so claude/codex/pi driving it produced 0 tool
 * calls → 0 findings. The CLI carries the loop natively. A later iteration
 * can point the CLI at the seat via `--api-key` / custom headers once the
 * bridge relays tools (see CURSOR_AGENT_* env below).
 *
 * Auth: the CLI uses whatever `cursor-agent` is logged into on the host
 * (login session in ~/.cursor), a `CURSOR_API_KEY`, or a `CURSOR_AUTH_TOKEN`
 * session token in the env — the last is what lets it run in a fresh
 * container with no interactive login. Nothing is injected by this plugin,
 * so `cursor` is intentionally NOT in preflight's KNOWN_BACKENDS
 * (assertAgentCredential no-ops for it).
 */

const DEFAULT_MODEL = "auto";
const DEBUG = process.env.DEEPSEC_AGENT_DEBUG === "1";

// Resolved per-spawn (not at module load) so tests can point at a fake CLI
// via CURSOR_AGENT_BIN after import.
function cursorBin(): string {
  return process.env.CURSOR_AGENT_BIN || "cursor-agent";
}

// Map a `tool_call` event's inner key (readToolCall / globToolCall /
// shellToolCall / …) to a short human label for progress lines.
function toolLabel(toolCall: Record<string, unknown>): string {
  const key = Object.keys(toolCall).find((k) => k.endsWith("ToolCall"));
  if (!key) return "tool";
  const base = key.replace(/ToolCall$/, "");
  switch (base) {
    case "read":
      return "Read";
    case "glob":
      return "Glob";
    case "grep":
      return "Grep";
    case "shell":
      return "Bash";
    default:
      return base;
  }
}

// Pull a short target (path / pattern / command) out of a tool_call for the
// progress line, best-effort.
function toolTarget(toolCall: Record<string, unknown>): string {
  const key = Object.keys(toolCall).find((k) => k.endsWith("ToolCall"));
  if (!key) return "";
  const inner = (toolCall[key] as { args?: Record<string, unknown> })?.args ?? {};
  const raw =
    (inner.path as string) ||
    (inner.globPattern as string) ||
    (inner.pattern as string) ||
    (inner.command as string) ||
    "";
  const oneLine = String(raw).split("\n")[0] ?? "";
  return oneLine.split("/").slice(-3).join("/").slice(0, 120);
}

interface CursorUsage {
  inputTokens?: number;
  outputTokens?: number;
  cacheReadTokens?: number;
  cacheWriteTokens?: number;
}

function mapUsage(u: CursorUsage): BatchMeta["usage"] {
  return {
    inputTokens: u.inputTokens ?? 0,
    outputTokens: u.outputTokens ?? 0,
    cacheReadInputTokens: u.cacheReadTokens ?? 0,
    cacheCreationInputTokens: u.cacheWriteTokens ?? 0,
  };
}

interface CursorRunState {
  agentMessages: string[];
  toolUseCount: number;
  turnCount: number;
  sessionId?: string;
  usage?: BatchMeta["usage"];
  durationApiMs?: number;
  isError: boolean;
  errorMessage: string;
}

/**
 * Spawn `cursor-agent -p <prompt> --output-format stream-json` and stream
 * its JSONL events. Yields AgentProgress for tool calls; returns the
 * accumulated run state (assistant messages, usage, session id, errors).
 *
 * `--force` runs all tools without approval prompts and `--trust` skips the
 * workspace-trust prompt (both required for an unattended run on a fresh
 * checkout). The scan prompt tells the agent to only read; a read-only mode
 * + env allowlist are hardening follow-ups (see plugin header).
 */
async function* runCursor(
  prompt: string,
  projectRoot: string,
  model: string,
  signal: AbortSignal | undefined,
): AsyncGenerator<AgentProgress, CursorRunState> {
  const args = [
    "-p",
    prompt,
    "--output-format",
    "stream-json",
    "--force",
    "--trust",
    "--model",
    model,
  ];

  const state: CursorRunState = {
    agentMessages: [],
    toolUseCount: 0,
    turnCount: 0,
    isError: false,
    errorMessage: "",
  };

  const child = spawn(cursorBin(), args, {
    cwd: projectRoot,
    stdio: ["ignore", "pipe", "pipe"],
    env: process.env,
    signal,
  });

  let stderrTail = "";
  child.stderr?.on("data", (d) => {
    stderrTail = (stderrTail + d.toString()).slice(-4000);
  });

  // Buffer stdout and hand back complete JSON lines as they arrive. A queue
  // decouples the (sync) 'data' handler from the (async) generator consumer.
  const lineQueue: string[] = [];
  let resolveWaiter: (() => void) | null = null;
  let closed = false;
  let buf = "";

  const pushLines = (chunk: string) => {
    buf += chunk;
    let nl: number;
    while ((nl = buf.indexOf("\n")) !== -1) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (line) lineQueue.push(line);
    }
    resolveWaiter?.();
    resolveWaiter = null;
  };

  child.stdout?.on("data", (d) => pushLines(d.toString()));
  child.on("close", () => {
    if (buf.trim()) lineQueue.push(buf.trim());
    buf = "";
    closed = true;
    resolveWaiter?.();
    resolveWaiter = null;
  });
  child.on("error", (e) => {
    state.errorMessage = e.message;
    state.isError = true;
    closed = true;
    resolveWaiter?.();
    resolveWaiter = null;
  });

  while (true) {
    if (lineQueue.length === 0) {
      if (closed) break;
      await new Promise<void>((r) => {
        resolveWaiter = r;
      });
      continue;
    }
    const line = lineQueue.shift() as string;
    let ev: Record<string, unknown>;
    try {
      ev = JSON.parse(line);
    } catch {
      continue; // non-JSON noise
    }

    const type = ev.type as string;
    if (type === "system" && ev.subtype === "init") {
      state.sessionId = ev.session_id as string;
    } else if (type === "assistant") {
      const content =
        (ev.message as { content?: Array<{ type: string; text?: string }> })?.content ?? [];
      const text = content
        .filter((b) => b.type === "text")
        .map((b) => b.text ?? "")
        .join("");
      if (text) state.agentMessages.push(text);
      state.turnCount++;
    } else if (type === "tool_call" && ev.subtype === "started") {
      state.toolUseCount++;
      const tc = ev.tool_call as Record<string, unknown>;
      yield {
        type: "tool_use",
        message: `${toolLabel(tc)}: ${toolTarget(tc)}`,
      };
    } else if (type === "thinking" && ev.subtype === "completed" && DEBUG) {
      yield { type: "thinking", message: "reasoning…" };
    } else if (type === "result") {
      state.isError = !!ev.is_error;
      if (ev.usage) state.usage = mapUsage(ev.usage as CursorUsage);
      if (typeof ev.duration_api_ms === "number") state.durationApiMs = ev.duration_api_ms;
      // The final `result` text is the concatenation of all assistant text;
      // keep it as a fallback if no discrete assistant messages carried the
      // JSON block.
      if (state.agentMessages.length === 0 && typeof ev.result === "string") {
        state.agentMessages.push(ev.result);
      }
      if (ev.is_error && typeof ev.result === "string") state.errorMessage = ev.result;
    }
  }

  if (state.isError && !state.errorMessage) {
    state.errorMessage = stderrTail || "cursor-agent exited with error";
  }
  return state;
}

// Cursor CLI has Read/Glob/Shell tools natively (like Claude), so the base
// prompt mostly fits. A tiny preamble grounds the project root and pins the
// JSON-only output contract.
function cursorPreamble(projectRoot: string): string {
  return `## Environment

You are running inside the Cursor CLI agent (read-only investigation).

- **Project root**: \`${projectRoot}\`. File paths in "Target Files" are RELATIVE to it.
- **Tools**: you have Read, Glob and Shell (\`rg\`, \`cat\`, \`sed -n\`, \`grep -r\`). Read each target file fully before judging; trace imports with Shell. Do NOT modify any file.
- **Output**: end your final message with a single fenced \`\`\`json ... \`\`\` block matching the schema in "Output Format". Narration before it is fine; the JSON block must be in your final message.`;
}

function chooseFinalText(messages: string[]): string {
  if (messages.length === 0) return "";
  for (let i = messages.length - 1; i >= 0; i--) {
    if (/```json/.test(messages[i])) return messages[i];
  }
  const joined = messages.join("\n\n");
  if (/```json/.test(joined)) return joined;
  return messages[messages.length - 1] ?? "";
}

export class CursorCliPlugin implements AgentPlugin {
  type = "cursor";

  async *investigate(params: InvestigateParams): AsyncGenerator<AgentProgress, InvestigateOutput> {
    const { batch, projectRoot, promptTemplate, projectInfo, config, signal, projectId } = params;
    const model = (config.model as string) ?? DEFAULT_MODEL;

    yield {
      type: "started",
      message: `Investigating ${batch.length} file(s) with Cursor CLI (${model})`,
    };

    const basePrompt = buildInvestigatePrompt({ promptTemplate, projectInfo, batch });
    const prompt = `${cursorPreamble(projectRoot)}\n\n${basePrompt}`;
    const startTime = Date.now();

    const gen = runCursor(prompt, projectRoot, model, signal);
    let res = await gen.next();
    while (!res.done) {
      yield res.value;
      res = await gen.next();
    }
    const state = res.value;

    const durationMs = Date.now() - startTime;
    const sdkMeta: Partial<BatchMeta> = {
      numTurns: state.turnCount,
      agentSessionId: state.sessionId,
      usage: state.usage,
      durationApiMs: state.durationApiMs,
    };

    // Typed quota bail (best-effort — the CLI surfaces rate limits in the
    // error text / stderr).
    if (state.isError) {
      const quota = classifyQuotaError(state.errorMessage, undefined);
      if (quota) throw new QuotaExhaustedError(quota, state.errorMessage);
    }

    const resultText = chooseFinalText(state.agentMessages);
    if (!resultText) {
      throw new Error(
        `Cursor CLI produced no result. Last error: ${state.errorMessage || "(none captured)"}.`,
      );
    }

    let parsed: ParsedInvestigateResults;
    try {
      parsed = parseInvestigateResults(resultText, batch);
    } catch (err) {
      // One JSON-only repair pass — re-run the CLI with a repair prompt (no
      // thread resume in the CLI, so it's a fresh, cheap tool-less call).
      yield {
        type: "thinking",
        message: "Cursor returned non-JSON investigation output; requesting JSON-only repair",
      };
      const repairGen = runCursor(
        buildInvestigateJsonRepairPrompt(batch),
        projectRoot,
        model,
        signal,
      );
      let rr = await repairGen.next();
      while (!rr.done) rr = await repairGen.next();
      const repairText = chooseFinalText(rr.value.agentMessages);
      try {
        parsed = parseInvestigateResults(repairText, batch);
        yield { type: "thinking", message: "Cursor JSON repair succeeded" };
      } catch (repairErr) {
        const combined = jsonRepairFailureError(err, repairErr);
        writeParseFailureDebug({
          projectId,
          phase: "investigate",
          agentType: this.type,
          resultText: formatJsonRepairFailureDebugText(resultText, repairText),
          error: combined,
          batch,
        });
        throw combined;
      }
    }

    const tokensStr = state.usage
      ? ` ${state.usage.inputTokens + state.usage.outputTokens} tokens`
      : "";
    yield {
      type: "complete",
      message: `Investigation complete (${(durationMs / 1000).toFixed(1)}s, ${state.turnCount} turns, ${state.toolUseCount} tool calls${tokensStr})`,
    };

    return {
      results: parsed.results,
      meta: { durationMs, ...sdkMeta },
    };
  }

  async *revalidate(params: RevalidateParams): AsyncGenerator<AgentProgress, RevalidateOutput> {
    const { batch, projectRoot, projectInfo, config, force = false, signal, projectId } = params;
    const model = (config.model as string) ?? DEFAULT_MODEL;

    const built = buildRevalidatePrompt({ batch, projectRoot, projectInfo, force });
    const prompt = `${cursorPreamble(projectRoot)}\n\n${built.prompt}`;

    yield {
      type: "started",
      message: `Revalidating ${built.totalFindings} finding(s) across ${batch.length} file(s) with Cursor CLI (${model})`,
    };

    const startTime = Date.now();
    const gen = runCursor(prompt, projectRoot, model, signal);
    let res = await gen.next();
    while (!res.done) {
      yield res.value;
      res = await gen.next();
    }
    const state = res.value;
    const durationMs = Date.now() - startTime;
    const sdkMeta: Partial<BatchMeta> = {
      numTurns: state.turnCount,
      agentSessionId: state.sessionId,
      usage: state.usage,
      durationApiMs: state.durationApiMs,
    };

    if (state.isError) {
      const quota = classifyQuotaError(state.errorMessage, undefined);
      if (quota) throw new QuotaExhaustedError(quota, state.errorMessage);
    }

    const resultText = chooseFinalText(state.agentMessages);
    if (!resultText) {
      throw new Error(
        `Cursor CLI produced no revalidation result. Last error: ${state.errorMessage || "(none captured)"}.`,
      );
    }

    let verdicts: RevalidateVerdict[];
    try {
      verdicts = parseRevalidateVerdicts(resultText);
    } catch (err) {
      yield {
        type: "thinking",
        message: "Cursor returned non-JSON revalidation output; requesting JSON-only repair",
      };
      const repairGen = runCursor(buildRevalidateJsonRepairPrompt(), projectRoot, model, signal);
      let rr = await repairGen.next();
      while (!rr.done) rr = await repairGen.next();
      const repairText = chooseFinalText(rr.value.agentMessages);
      try {
        verdicts = parseRevalidateVerdicts(repairText);
        yield { type: "thinking", message: "Cursor JSON repair succeeded" };
      } catch (repairErr) {
        const combined = jsonRepairFailureError(err, repairErr);
        writeParseFailureDebug({
          projectId,
          phase: "revalidate",
          agentType: this.type,
          resultText: formatJsonRepairFailureDebugText(resultText, repairText),
          error: combined,
          batch,
        });
        throw combined;
      }
    }

    yield {
      type: "complete",
      message: `Revalidation complete (${(durationMs / 1000).toFixed(1)}s, ${state.turnCount} turns, ${verdicts.length} verdicts)`,
    };

    return { verdicts, meta: { durationMs, ...sdkMeta } };
  }
}

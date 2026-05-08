import * as crypto from "node:crypto";
import * as fs from "node:fs";
import { createRequire } from "node:module";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import type { RefusalReport } from "@deepsec/core";
import {
  Codex,
  type CodexOptions,
  type ModelReasoningEffort,
  type ThreadEvent,
  type ThreadItem,
} from "@openai/codex-sdk";
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

const DEFAULT_MODEL = "gpt-5.5";
const DEFAULT_EFFORT: ModelReasoningEffort = "xhigh";

/**
 * Pick a Codex sandbox mode based on whether the orchestrator is already
 * running inside a Vercel Sandbox microVM (signalled by
 * DEEPSEC_INSIDE_SANDBOX, set in setup.ts's `buildSandboxEnv`).
 *
 * - In-VM: `danger-full-access` — the VM is the boundary, and Codex's
 *   nested read-only sandbox was rejecting ~7% of cat/sed/rg calls under
 *   `approvalPolicy: "never"` (no fallback path when an op needs
 *   escalation).
 * - Local: `workspace-write` — allows reads anywhere, writes within the
 *   project, and shell execution without any approval prompts. Combined
 *   with `networkAccessEnabled: false` the agent's Bash still can't reach
 *   the network. This is the safety boundary we want when the agent is
 *   running directly on the user's laptop.
 */
function pickSandboxMode(): "danger-full-access" | "workspace-write" {
  return process.env.DEEPSEC_INSIDE_SANDBOX === "1" ? "danger-full-access" : "workspace-write";
}

/**
 * Codex CLI's built-in `openai` provider defaults to the WebSocket Responses
 * transport (wss://.../responses). AI Gateway doesn't expose that, so the
 * CLI gets stuck in a reconnect loop on 404. Codex also rejects any attempt
 * to override built-in providers ("Built-in providers cannot be overridden.
 * Rename your custom provider"). The fix: define a custom provider with the
 * gateway base_url and supports_websockets=false, and route the default
 * model through it.
 */
const CUSTOM_PROVIDER_ID = "ai_gateway";

// Set by the `--ollama` CLI flag (DEEPSEC_OLLAMA=1). Explicit opt-in
// only; we don't autodetect Ollama from the model name.
function ollamaRequested(): boolean {
  const v = process.env.DEEPSEC_OLLAMA?.trim().toLowerCase();
  return v === "1" || v === "true";
}

/**
 * The codex CLI persists thread state to `$CODEX_HOME/sessions/` (defaulting
 * to `~/.codex`). Multiple concurrent codex CLI processes within one host
 * stomp on each other's session DB — empirically observed as ~99% of runs
 * completing in ~1s with 1 turn / 0 tool calls / 0 tokens / $0 (the CLI
 * silently no-ops when its session writes fail).
 *
 * Fix: give every Codex SDK instance a unique CODEX_HOME, keyed off PID +
 * a counter + random bytes. Tempdirs auto-cleanup on process exit; even if
 * a few leak they're tiny.
 */
// mkdtempSync creates a 0700 directory atomically (and refuses if the
// target already exists), which closes the symlink-clobber race a
// pre-creating local attacker would otherwise win.
function makeCodexHome(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "codex-home-"));
}

/**
 * Locate a usable `~/.codex/auth.json` for subscription-mode auth (the user
 * has run `codex login` on the laptop and we want to reuse that session
 * instead of forcing them to set OPENAI_API_KEY).
 *
 * Returns the parent dir (the "user codex home"), or null if no auth file
 * is present. Honors `CODEX_HOME` for users who run codex with a
 * non-default data dir; we look for auth.json in that override before
 * falling back to `$HOME/.codex`.
 */
function findCodexSubscriptionAuth(): string | null {
  const candidates: string[] = [];
  if (process.env.CODEX_HOME) candidates.push(process.env.CODEX_HOME);
  candidates.push(path.join(os.homedir(), ".codex"));
  for (const dir of candidates) {
    if (fs.existsSync(path.join(dir, "auth.json"))) return dir;
  }
  return null;
}

/**
 * Mirror the user's auth.json into our per-invocation CODEX_HOME so the
 * codex CLI sees their subscription credentials while still writing
 * sessions/* into the isolated tempdir. We prefer a symlink so token
 * refresh writes propagate back to the user's real auth.json — only fall
 * back to copy on platforms/filesystems that can't symlink (e.g. some
 * Windows configurations).
 *
 * config.toml is intentionally NOT mirrored: a user-supplied
 * `model_provider = "..."` could conflict with our defaults, and we
 * specifically want the built-in `openai` provider in subscription mode.
 */
function mirrorCodexAuthJson(userCodexHome: string, codexHome: string): void {
  const src = path.join(userCodexHome, "auth.json");
  const dst = path.join(codexHome, "auth.json");
  try {
    fs.symlinkSync(src, dst);
  } catch {
    fs.copyFileSync(src, dst);
  }
}

// Create the stderr log atomically with O_EXCL + 0600 so a pre-created
// symlink at the chosen path causes failure rather than redirecting our
// writes through it. The 16-byte CSPRNG suffix replaces Math.random(),
// whose internal state is recoverable from a small number of observed
// outputs.
function makeStderrLog(): string {
  for (let attempt = 0; attempt < 5; attempt++) {
    const id = crypto.randomBytes(16).toString("hex");
    const p = path.join(os.tmpdir(), `codex-stderr-${id}.log`);
    try {
      const fd = fs.openSync(p, "wx", 0o600);
      fs.closeSync(fd);
      return p;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
    }
  }
  throw new Error("Failed to create stderr log after 5 attempts");
}

/**
 * Resolve paths to (a) our stderr-capturing wrapper script and (b) the real
 * codex bin script. The wrapper lives next to this module; the real codex
 * bin is resolved from the SDK's runtime dependency tree.
 *
 * Cached after first resolution; on Linux/sandbox the wrapper needs +x —
 * we ensure the perms once.
 */
let cachedPaths: { wrapper: string; realBin: string } | null = null;

function resolveCodexPaths(): { wrapper: string; realBin: string } | null {
  if (cachedPaths) return cachedPaths;
  // codex SDK calls plain spawn() with no shell:true. On Windows that
  // rejects .sh (EFTYPE) and Node's BatBadBut fix rejects .cmd
  // (EINVAL). Fall through to codex.exe; stderr capture goes inert.
  if (process.platform === "win32") return null;
  try {
    const here = path.dirname(fileURLToPath(import.meta.url));
    // Wrapper sits next to the source. After tsc, the .js lives in dist/
    // and the .sh stays in src/ — try both.
    const wrapperCandidates = [
      path.resolve(here, "codex-wrapper.sh"),
      path.resolve(here, "../../src/agents/codex-wrapper.sh"),
      path.resolve(here, "../src/agents/codex-wrapper.sh"),
    ];
    const wrapper = wrapperCandidates.find((p) => fs.existsSync(p));
    if (!wrapper) return null;
    try {
      fs.chmodSync(wrapper, 0o755);
    } catch {}

    const require = createRequire(import.meta.url);
    const realBin = require.resolve("@openai/codex/bin/codex.js");
    cachedPaths = { wrapper, realBin };
    return cachedPaths;
  } catch {
    return null;
  }
}

/**
 * Variables the codex CLI / spawned shell legitimately needs. Anything
 * outside this set is dropped before the agent process inherits the
 * environment — defense against prompt-injection-driven exfiltration
 * via `env` / `printenv` / `cat /proc/self/environ`.
 *
 * Adding new entries: only do so if codex genuinely fails without them.
 * Values matching `*_TOKEN`, `*_KEY`, `*_SECRET`, `*_PASSWORD` should
 * basically never be added — the model has unrestricted Bash and we
 * cannot trust prompt-level instructions to keep its hands off them.
 */
const CODEX_ENV_ALLOWLIST = new Set<string>([
  // Shell + locale
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
  // Node/JS toolchain (codex CLI is node)
  "NODE_PATH",
  "NODE_OPTIONS",
  "NPM_CONFIG_USERCONFIG",
  // Rust tracing (codex's Rust binary respects RUST_LOG/RUST_BACKTRACE)
  "RUST_LOG",
  "RUST_BACKTRACE",
  // Codex itself
  "CODEX_HOME",
  // OLLAMA_API_KEY is forwarded explicitly via `extras` only in Ollama mode.
  "OLLAMA_HOST",
  // Our wrapper
  "CODEX_REAL_BIN",
  "CODEX_STDERR_LOG",
  // Debug toggle (mirrors what claude-agent-sdk respects)
  "DEBUG_CLAUDE_AGENT_SDK",
]);

/**
 * Allowlist match for keys whose names start with a known-safe prefix.
 * Useful for cases like `LC_*` we already enumerate, plus a few
 * codex-specific knobs that may grow over time.
 */
const CODEX_ENV_ALLOWLIST_PREFIXES = ["LC_"];

/**
 * Build the env passed to the codex child process. The SDK's `env`
 * option REPLACES process.env (no merge), so we explicitly construct a
 * minimal environment: allowlisted basics + caller-supplied extras
 * (CODEX_HOME, wrapper paths) + the credential variable codex actually
 * needs in the current mode.
 *
 * Crucially, this means the agent's Bash tool can NOT see CI secrets
 * (GITHUB_TOKEN, AWS_*, *_API_KEY, etc.) that the orchestrator process
 * received. Only the credential explicitly forwarded via `extras`
 * reaches the agent.
 */
function buildCodexEnv(extras: Record<string, string>): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (typeof v !== "string") continue;
    if (CODEX_ENV_ALLOWLIST.has(k) || CODEX_ENV_ALLOWLIST_PREFIXES.some((p) => k.startsWith(p))) {
      env[k] = v;
    }
  }
  Object.assign(env, extras);
  return env;
}

interface CodexInvocation {
  options: CodexOptions;
  stderrLog: string | null;
  /** Tempdir under /tmp that was created for this invocation; cleanup on exit */
  codexHome: string;
}

function buildCodexInvocation(): CodexInvocation {
  // Decide between gateway mode (orchestrator has an API token, we route
  // through Vercel AI Gateway via a custom provider) and subscription mode
  // (no token but the user has run `codex login` on this machine — let
  // codex use its default openai provider against their session). Sandbox
  // workers always go gateway; the preflight ensures a token is present
  // before we ever get here in that path. `--ollama` is a third mode
  // that bypasses both and selects codex's built-in `ollama` provider.
  const ollamaMode = ollamaRequested();
  const haveApiToken = !!(process.env.OPENAI_API_KEY || process.env.ANTHROPIC_AUTH_TOKEN);
  const subscriptionHome = ollamaMode || haveApiToken ? null : findCodexSubscriptionAuth();

  const codexHome = makeCodexHome();
  if (subscriptionHome) {
    mirrorCodexAuthJson(subscriptionHome, codexHome);
  }

  const extras: Record<string, string> = { CODEX_HOME: codexHome };

  // Wrap codex with our stderr-capturing shim so we can diagnose silent
  // failures (codex CLI exits clean with empty turns and the SDK swallows
  // stderr on exit=0). Only enables if the wrapper resolves cleanly.
  let stderrLog: string | null = null;
  let codexPathOverride: string | undefined;
  const paths = resolveCodexPaths();
  if (paths) {
    stderrLog = makeStderrLog();
    extras.CODEX_REAL_BIN = paths.realBin;
    extras.CODEX_STDERR_LOG = stderrLog;
    codexPathOverride = paths.wrapper;
    // RUST_LOG turns on tracing in the codex Rust binary so the captured
    // stderr actually contains useful info (HTTP status, retry attempts).
    if (!process.env.RUST_LOG) extras.RUST_LOG = "info";
  }

  if (subscriptionHome) {
    // No credentials enter the codex env in subscription mode — auth
    // happens via the mirrored auth.json. The allowlist already drops
    // OPENAI_API_KEY/ANTHROPIC_AUTH_TOKEN/_BASE_URL, so no explicit
    // delete is needed.
    const env = buildCodexEnv(extras);
    const options: CodexOptions = { env };
    if (codexPathOverride) options.codexPathOverride = codexPathOverride;
    return { options, stderrLog, codexHome };
  }

  if (ollamaMode) {
    // codex 0.125 ships a built-in `ollama` provider; selecting it is
    // the SDK equivalent of `codex --oss`. The provider routes
    // local-daemon vs Ollama Cloud via the model name's `:cloud` suffix.
    if (process.env.OLLAMA_API_KEY) extras.OLLAMA_API_KEY = process.env.OLLAMA_API_KEY;
    const options: CodexOptions = {
      config: { model_provider: "ollama" },
      env: buildCodexEnv(extras),
    };
    if (codexPathOverride) options.codexPathOverride = codexPathOverride;
    return { options, stderrLog, codexHome };
  }

  // Gateway mode (default): AI Gateway exposes an OpenAI-compatible
  // endpoint. Both vars are honored; OPENAI_BASE_URL takes precedence
  // when both are set.
  const baseUrl = process.env.OPENAI_BASE_URL ?? process.env.ANTHROPIC_BASE_URL ?? undefined;
  const apiKey = process.env.OPENAI_API_KEY ?? process.env.ANTHROPIC_AUTH_TOKEN ?? undefined;

  const providerConfig: Record<string, string | boolean> = {
    name: "Vercel AI Gateway (OpenAI-compat)",
    env_key: "OPENAI_API_KEY",
    wire_api: "responses",
    supports_websockets: false,
  };
  // Codex appends `/responses` (and `/models` for listing) directly to
  // base_url, so base_url MUST include `/v1` — final URL needs to be
  // `<gateway>/v1/responses`. We tolerate either form coming in via env.
  if (baseUrl) {
    const trimmed = baseUrl.replace(/\/$/, "");
    providerConfig.base_url = /\/v1$/.test(trimmed) ? trimmed : `${trimmed}/v1`;
  }

  const config = {
    model_provider: CUSTOM_PROVIDER_ID,
    model_providers: {
      [CUSTOM_PROVIDER_ID]: providerConfig,
    },
  };

  // Forward ONLY the credential codex actually needs via env. The
  // allowlist drops every other secret in process.env, so prompt
  // injection via repository content can't exfiltrate GITHUB_TOKEN,
  // AWS_*, etc. — the agent's Bash sees just this one key value
  // (which it needs anyway to talk to the gateway) plus shell basics.
  if (apiKey) extras.OPENAI_API_KEY = apiKey;

  // Don't pass baseUrl as an SDK option — that would emit
  // `openai_base_url=...` which only affects the built-in openai provider
  // we are explicitly avoiding.
  const options: CodexOptions = {
    apiKey,
    config,
    env: buildCodexEnv(extras),
  };
  if (codexPathOverride) options.codexPathOverride = codexPathOverride;
  return { options, stderrLog, codexHome };
}

/**
 * Delete the per-invocation CODEX_HOME tempdir. Without this, /tmp fills
 * up over a long run and codex's bootstrap writes start failing silently
 * (the SDK surfaces this as the now-familiar zero-token silent failure).
 */
function cleanupCodexHome(dir: string): void {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch {}
}

/**
 * Read the captured stderr log. Returns `undefined` if missing/empty.
 * Caps to ~3000 chars (kept inside BatchMeta and yielded to progress).
 */
function readStderrTail(p: string | null): string | undefined {
  if (!p) return undefined;
  try {
    const buf = fs.readFileSync(p, "utf-8");
    const trimmed = buf.trim();
    if (!trimmed) return undefined;
    if (trimmed.length <= 3000) return trimmed;
    return "…" + trimmed.slice(trimmed.length - 3000);
  } catch {
    return undefined;
  }
}

function cleanupStderrLog(p: string | null): void {
  if (!p) return;
  try {
    fs.unlinkSync(p);
  } catch {}
}

function shortPath(p: string): string {
  return p.split("/").slice(-3).join("/");
}

/**
 * Map a Codex thread item to one of our progress events. Returns `undefined`
 * for items we don't surface (turn-internal noise).
 */
/**
 * When `DEEPSEC_AGENT_DEBUG=1` is set, surface a lot more raw signal:
 *   - command_execution: include exit code + a tail of aggregated_output
 *   - agent_message: emit the full text (so we can see what's being captured
 *     as resultText vs lost as narration)
 *   - reasoning: longer excerpt
 *   - turn.completed: detailed token + cost breakdown
 *   - parse step: report whether the captured text contains a JSON block,
 *     length, and which filePaths the parser matched vs missed
 */
const DEBUG = process.env.DEEPSEC_AGENT_DEBUG === "1";

const REASONING_LEN = DEBUG ? 1200 : 200;
const COMMAND_LEN = DEBUG ? 400 : 120;
const OUTPUT_LEN = DEBUG ? 600 : 0;
const AGENT_MSG_LEN = DEBUG ? 4000 : 0;

function tail(s: string | undefined, n: number): string {
  if (!s) return "";
  if (s.length <= n) return s;
  return "…" + s.slice(s.length - n);
}

function itemToProgress(item: ThreadItem): AgentProgress | undefined {
  switch (item.type) {
    case "command_execution": {
      const cmd = item.command ?? "";
      const head = cmd.split("\n")[0]?.slice(0, COMMAND_LEN) ?? "";
      let suffix = "";
      if (DEBUG) {
        const parts: string[] = [];
        if (item.exit_code !== undefined) parts.push(`exit=${item.exit_code}`);
        if (item.status) parts.push(item.status);
        const out = tail(item.aggregated_output, OUTPUT_LEN).replace(/\n+/g, "\\n");
        if (out) parts.push(`out=${out}`);
        if (parts.length) suffix = `  [${parts.join(" ")}]`;
      }
      return {
        type: "tool_use",
        message: `bash: ${head}${suffix}`,
      };
    }
    case "file_change": {
      const paths = item.changes
        .slice(0, 3)
        .map((c) => `${c.kind} ${shortPath(c.path)}`)
        .join(", ");
      return {
        type: "tool_use",
        message: `file_change: ${paths}${DEBUG ? `  [status=${item.status}]` : ""}`,
      };
    }
    case "mcp_tool_call":
      return {
        type: "tool_use",
        message: `${item.server}/${item.tool}${DEBUG ? `  [status=${item.status}]` : ""}`,
      };
    case "web_search":
      return {
        type: "tool_use",
        message: `web_search: ${item.query.slice(0, 100)}`,
      };
    case "reasoning":
      return {
        type: "thinking",
        message: item.text.slice(0, REASONING_LEN),
      };
    case "todo_list": {
      const total = item.items.length;
      const done = item.items.filter((t) => t.completed).length;
      const next = item.items.find((t) => !t.completed)?.text;
      return {
        type: "thinking",
        message: `todo ${done}/${total}${next ? `: ${next.slice(0, 120)}` : ""}`,
      };
    }
    case "error":
      return { type: "error", message: `Codex item error: ${item.message.slice(0, 300)}` };
    case "agent_message": {
      if (!DEBUG) return undefined;
      const text = item.text ?? "";
      const looksJson = /```json|^\s*\[/m.test(text);
      const head = text.slice(0, AGENT_MSG_LEN);
      return {
        type: "thinking",
        message: `agent_message (${text.length} chars, json=${looksJson}): ${head}${text.length > AGENT_MSG_LEN ? "…" : ""}`,
      };
    }
  }
  return undefined;
}

/**
 * Per-1M-token rates for cost estimation. Codex (OpenAI Responses API)
 * doesn't return cost like Anthropic does, so we compute it here.
 *
 * Source: https://developers.openai.com/api/docs/pricing (April 2026).
 * Update when OpenAI repprices or new GPT-5.x SKUs ship.
 */
const MODEL_PRICING_USD_PER_M_TOKENS: Record<
  string,
  { input: number; cachedInput: number; output: number }
> = {
  "gpt-5.5": { input: 5.0, cachedInput: 0.5, output: 30.0 },
  "gpt-5.5-pro": { input: 30.0, cachedInput: 30.0, output: 180.0 }, // pro tier has no cached discount today
  "gpt-5.4": { input: 2.5, cachedInput: 0.25, output: 15.0 },
  "gpt-5.4-mini": { input: 0.75, cachedInput: 0.075, output: 4.5 },
  "gpt-5.4-nano": { input: 0.2, cachedInput: 0.02, output: 1.25 },
  "gpt-5.4-pro": { input: 30.0, cachedInput: 30.0, output: 180.0 },
};

interface CodexUsage {
  input_tokens: number;
  cached_input_tokens: number;
  output_tokens: number;
  reasoning_output_tokens: number;
}

/**
 * OpenAI Responses API convention:
 *   - `input_tokens` = total input (cached + uncached)
 *   - `cached_input_tokens` = subset billed at the cached rate
 *   - `output_tokens` = total output (visible + reasoning)
 *   - `reasoning_output_tokens` = subset, informational only — already
 *     included in output_tokens, so DON'T double-count.
 *
 * Our internal `inputTokens` follows the Anthropic convention: uncached
 * input only. Subtract the cached portion so downstream rollups (cost,
 * cache hit rate) don't double-count it.
 */
function mapUsage(usage: CodexUsage) {
  const cached = usage.cached_input_tokens ?? 0;
  const totalInput = usage.input_tokens ?? 0;
  return {
    inputTokens: Math.max(0, totalInput - cached),
    outputTokens: usage.output_tokens ?? 0,
    cacheReadInputTokens: cached,
    cacheCreationInputTokens: 0,
  };
}

/**
 * Codex emits multiple `agent_message` items during a turn — narration like
 * "Reading file X…" interleaved with the actual JSON response. The last
 * message wins isn't safe (the trailing message is often "Done." or some
 * conversational footer). Pick the last message that contains a fenced
 * JSON block; fall back to the last message overall; fall back to the
 * concatenation of all of them so the regex parser can still find the
 * block if the model split it across narration.
 */
/**
 * The shared investigation prompt was written for Claude (mentions "Read
 * tool", "Glob", "Grep"). Codex uses shell `command_execution` instead, and
 * we observed agents repeatedly running `pwd` because they were unsure where
 * relative paths resolved to. Prepending an environment block grounds them.
 */
function codexEnvironmentPreamble(projectRoot: string): string {
  return `## Environment

You are running inside the Codex CLI on a Linux sandbox (read-only mode, no network access).

- **Project root** (the codebase under investigation): \`${projectRoot}\`
  - File paths in the "Target Files" list below are RELATIVE to this root.
  - When you read a file, ALWAYS resolve it against this root — either by \`cd ${projectRoot}\` once at the start, or by using absolute paths like \`${projectRoot}/<relative-path>\`.
  - Do NOT run \`pwd\` repeatedly to figure out where you are; the working directory is what's stated above.
- **Available tools**: shell only. Use \`cat\`, \`sed -n\`, \`rg\` (ripgrep — installed; preferred over grep for tree-wide search), \`grep -r\`, \`fd\` / \`find\`, \`head\`, \`wc\`, \`python3\` (installed, useful for parsing JSON / AST when shell isn't enough). There is no dedicated "Read"/"Glob"/"Grep" tool — those are conceptual references in the instructions below. Use shell equivalents.
- **Investigation discipline**: Read each target file fully. Trace imports. Don't guess at content; verify with the shell.
- **Output**: end your turn with a single fenced \`\`\`json ... \`\`\` block matching the schema in "Output Format". Do NOT split the JSON across multiple messages. Conversational narration before the JSON is fine; the JSON block must appear in your final message.`;
}

function chooseFinalText(messages: string[]): string {
  if (messages.length === 0) return "";
  for (let i = messages.length - 1; i >= 0; i--) {
    if (/```json/.test(messages[i])) return messages[i];
  }
  // No fenced JSON in any individual message — try the concatenation.
  const joined = messages.join("\n\n");
  if (/```json/.test(joined)) return joined;
  return messages[messages.length - 1] ?? "";
}

function estimateCostUsd(model: string, usage: CodexUsage): number | undefined {
  const rates = MODEL_PRICING_USD_PER_M_TOKENS[model];
  if (!rates) return undefined;
  const cached = usage.cached_input_tokens ?? 0;
  const uncachedInput = Math.max(0, (usage.input_tokens ?? 0) - cached);
  const output = usage.output_tokens ?? 0;
  return (
    (uncachedInput * rates.input + cached * rates.cachedInput + output * rates.output) / 1_000_000
  );
}

async function runRefusalFollowUp(
  codex: Codex,
  threadId: string | undefined,
  projectRoot: string,
  model: string,
): Promise<RefusalReport | undefined> {
  if (!threadId) return undefined;

  let raw = "";
  try {
    const thread = codex.resumeThread(threadId, {
      model,
      workingDirectory: projectRoot,
      skipGitRepoCheck: true,
      sandboxMode: "read-only",
      approvalPolicy: "never",
      networkAccessEnabled: false,
      modelReasoningEffort: "low",
    });
    const turn = await thread.run(REFUSAL_FOLLOWUP_PROMPT);
    raw = turn.finalResponse ?? "";
  } catch {
    return undefined;
  }

  return parseRefusalReport(raw);
}

export class CodexAgentSdkPlugin implements AgentPlugin {
  type = "codex";

  async *investigate(params: InvestigateParams): AsyncGenerator<AgentProgress, InvestigateOutput> {
    const { batch, projectRoot, promptTemplate, projectInfo, config, signal } = params;
    const model = (config.model as string) ?? DEFAULT_MODEL;
    const effort = (config.reasoningEffort as ModelReasoningEffort) ?? DEFAULT_EFFORT;

    yield {
      type: "started",
      message: `Investigating ${batch.length} file(s) with Codex SDK (${model}, effort=${effort})`,
    };

    const basePrompt = buildInvestigatePrompt({ promptTemplate, projectInfo, batch });
    const prompt = `${codexEnvironmentPreamble(projectRoot)}\n\n${basePrompt}`;
    const invocation = buildCodexInvocation();
    // Idempotent cleanup the finally block runs whether we exit via return,
    // throw, or generator close. Each helper swallows missing-target errors,
    // so calling them twice is safe.
    let cleanedUp = false;
    const cleanup = (): void => {
      if (cleanedUp) return;
      cleanedUp = true;
      cleanupStderrLog(invocation.stderrLog);
      cleanupCodexHome(invocation.codexHome);
    };
    const codex = new Codex(invocation.options);
    const startTime = Date.now();
    let agentMessages: string[] = [];
    let threadId: string | undefined;
    let turnCount = 0;
    let toolUseCount = 0;
    let sdkMeta: Partial<BatchMeta> = {};
    let lastError = "";

    try {
      for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        if (attempt > 1) {
          yield {
            type: "thinking" as const,
            message: `Retrying batch after transient error (attempt ${attempt}/${MAX_ATTEMPTS}): ${lastError.slice(0, 200)}`,
          };
          agentMessages = [];
          threadId = undefined;
          turnCount = 0;
          toolUseCount = 0;
          sdkMeta = {};
          lastError = "";
        }

        try {
          const thread = codex.startThread({
            model,
            workingDirectory: projectRoot,
            skipGitRepoCheck: true,
            // sandboxMode: in-VM uses `danger-full-access` (the VM is the
            // boundary; the nested read-only sandbox was failing on ~7% of
            // cat/sed/rg calls under approvalPolicy=never). Local uses
            // `workspace-write` — reads anywhere, writes inside the project,
            // shell allowed; networkAccessEnabled stays false either way so
            // the agent's Bash still can't reach the network.
            sandboxMode: pickSandboxMode(),
            approvalPolicy: "never",
            networkAccessEnabled: false,
            modelReasoningEffort: effort,
            webSearchEnabled: false,
          });
          const { events } = await thread.runStreamed(prompt, { signal });

          for await (const event of events as AsyncGenerator<ThreadEvent>) {
            switch (event.type) {
              case "thread.started":
                threadId = event.thread_id;
                break;

              case "turn.started":
                turnCount++;
                break;

              case "item.completed": {
                const prog = itemToProgress(event.item);
                if (prog) {
                  if (prog.type === "tool_use") toolUseCount++;
                  yield prog;
                }
                if (event.item.type === "agent_message") {
                  agentMessages.push(event.item.text ?? "");
                }
                break;
              }

              case "turn.completed":
                if (event.usage) {
                  sdkMeta.usage = mapUsage(event.usage);
                  const turnCost = estimateCostUsd(model, event.usage);
                  if (turnCost !== undefined) {
                    sdkMeta.costUsd = (sdkMeta.costUsd ?? 0) + turnCost;
                  }
                }
                sdkMeta.numTurns = turnCount;
                sdkMeta.agentSessionId = threadId ?? thread.id ?? undefined;
                break;

              case "turn.failed":
                lastError = event.error?.message ?? "turn.failed";
                yield {
                  type: "error" as const,
                  message: `Codex turn failed: ${lastError.slice(0, 300)}`,
                };
                break;

              case "error":
                lastError = event.message;
                yield {
                  type: "error" as const,
                  message: `Codex stream error: ${lastError.slice(0, 300)}`,
                };
                break;
            }
          }
        } catch (sdkErr) {
          lastError = sdkErr instanceof Error ? sdkErr.message : String(sdkErr);
          yield {
            type: "error" as const,
            message: `Codex SDK error: ${lastError.slice(0, 300)}`,
          };
        }

        if (agentMessages.length > 0) break;
        // Codex frequently exits silent on quota/auth errors — the SDK
        // returns an empty `response.completed` and the error only lives in
        // the wrapper-captured stderr. Read it BEFORE deciding to retry so
        // a quota miss bails fast instead of burning all 3 attempts.
        const stderrPeek = readStderrTail(invocation.stderrLog) ?? "";
        const quotaSourceEarly =
          classifyQuotaError(lastError, "codex") || classifyQuotaError(stderrPeek, "codex");
        if (quotaSourceEarly) {
          // Stash the stderr so the throw below can include it for ops.
          if (stderrPeek) sdkMeta.codexStderr = stderrPeek;
          throw new QuotaExhaustedError(
            quotaSourceEarly,
            lastError || stderrPeek || "codex silent quota exit",
          );
        }
        // Silent-failure retry: gateway returned response.completed with 0
        // tokens and no agent_message — codex CLI exited clean, but no work
        // happened. Retry as if it were a transient error.
        const sawSilentFailure =
          agentMessages.length === 0 && (sdkMeta.usage?.outputTokens ?? 0) === 0;
        const shouldRetry =
          attempt < MAX_ATTEMPTS && (isTransientError(lastError) || sawSilentFailure);
        if (!shouldRetry) break;
        if (sawSilentFailure && !lastError) {
          yield {
            type: "thinking" as const,
            message: `Codex returned empty completion (likely gateway soft-fail) — retrying with backoff (attempt ${attempt}/${MAX_ATTEMPTS})`,
          };
        }
        await backoff(attempt);
      }

      const resultText = chooseFinalText(agentMessages);

      if (DEBUG) {
        const hasJson = /```json/.test(resultText);
        yield {
          type: "thinking",
          message: `[debug] resultText: ${agentMessages.length} agent_message(s), final length=${resultText.length}, hasJson=${hasJson}`,
        };
      }

      const durationMs = Date.now() - startTime;
      const tokensStr = sdkMeta.usage
        ? ` ${sdkMeta.usage.inputTokens + sdkMeta.usage.outputTokens} tokens`
        : "";
      const costStr = sdkMeta.costUsd != null ? ` $${sdkMeta.costUsd.toFixed(3)}` : "";

      // Silent-failure detection: 0 output tokens means codex CLI didn't
      // produce anything useful. Surface the captured stderr so we can see
      // why (rate-limit, auth error, network, etc.). Always log the
      // wrapper-captured output on silent — it's our only diagnostic path.
      const wasSilent = (sdkMeta.usage?.outputTokens ?? 0) === 0;
      const stderrTail = wasSilent ? readStderrTail(invocation.stderrLog) : undefined;
      if (wasSilent && stderrTail) {
        yield {
          type: "error" as const,
          message: `Codex silent-exit stderr: ${stderrTail.slice(0, 1500)}`,
        };
        sdkMeta.codexStderr = stderrTail;
        // Final-pass classification: if all retries finished and the
        // stderr now carries a quota signature we missed mid-loop, throw
        // the typed error so the processor stops launching new batches.
        const quotaSourceFinal = classifyQuotaError(stderrTail, "codex");
        if (quotaSourceFinal) {
          throw new QuotaExhaustedError(quotaSourceFinal, stderrTail);
        }
      }
      const refusal = await runRefusalFollowUp(codex, threadId, projectRoot, model);
      if (refusal?.refused) {
        yield {
          type: "thinking" as const,
          message: `Refusal detected: ${refusal.reason ?? refusal.skipped?.map((s) => s.filePath ?? "?").join(", ") ?? "see raw"}`,
        };
      }

      // Empty-result check runs BEFORE parse so a silent failure throws
      // with the captured stderr instead of crashing inside the parser
      // with a misleading "no JSON in response" message — and the finally
      // block below cleans up regardless of which path we exit through.
      if (!resultText) {
        const stderrSuffix = sdkMeta.codexStderr
          ? ` Stderr tail: ${sdkMeta.codexStderr.slice(0, 800)}`
          : "";
        throw new Error(
          `Codex SDK produced no result after ${MAX_ATTEMPTS} attempt(s). ` +
            `Last error: ${lastError || "(none captured)"}.${stderrSuffix}`,
        );
      }

      const parsed = parseInvestigateResults(resultText, batch);
      if (DEBUG) {
        const matched = parsed.filter((r) => r.findings.length > 0).length;
        const totalFindings = parsed.reduce((s, r) => s + r.findings.length, 0);
        yield {
          type: "thinking",
          message: `[debug] parsed: ${parsed.length} entries, ${matched} with findings, ${totalFindings} total findings`,
        };
      }

      yield {
        type: "complete",
        message: `Investigation complete (${(durationMs / 1000).toFixed(1)}s, ${turnCount} turns, ${toolUseCount} tool calls${costStr}${tokensStr}${refusal?.refused ? " ⚠️  refusal" : ""})`,
      };

      return {
        results: parsed,
        meta: {
          durationMs,
          ...sdkMeta,
          refusal,
        },
      };
    } finally {
      // Always release CODEX_HOME / stderr log — the previous flow
      // skipped cleanup whenever parseInvestigateResults threw.
      cleanup();
    }
  }

  async *revalidate(params: RevalidateParams): AsyncGenerator<AgentProgress, RevalidateOutput> {
    const { batch, projectRoot, projectInfo, config, force = false, signal } = params;
    const model = (config.model as string) ?? DEFAULT_MODEL;
    const effort = (config.reasoningEffort as ModelReasoningEffort) ?? DEFAULT_EFFORT;

    const built = buildRevalidatePrompt({
      batch,
      projectRoot,
      projectInfo,
      force,
    });
    const totalFindings = built.totalFindings;
    const prompt = `${codexEnvironmentPreamble(projectRoot)}\n\n${built.prompt}`;

    yield {
      type: "started",
      message: `Revalidating ${totalFindings} finding(s) across ${batch.length} file(s) with Codex SDK (${model})`,
    };

    const invocation = buildCodexInvocation();
    let cleanedUp = false;
    const cleanup = (): void => {
      if (cleanedUp) return;
      cleanedUp = true;
      cleanupStderrLog(invocation.stderrLog);
      cleanupCodexHome(invocation.codexHome);
    };
    const codex = new Codex(invocation.options);
    const startTime = Date.now();
    let agentMessages: string[] = [];
    let threadId: string | undefined;
    let turnCount = 0;
    let sdkMeta: Partial<BatchMeta> = {};
    let lastError = "";

    try {
      for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        if (attempt > 1) {
          yield {
            type: "thinking" as const,
            message: `Retrying revalidation batch after transient error (attempt ${attempt}/${MAX_ATTEMPTS}): ${lastError.slice(0, 200)}`,
          };
          agentMessages = [];
          threadId = undefined;
          turnCount = 0;
          sdkMeta = {};
          lastError = "";
        }

        try {
          const thread = codex.startThread({
            model,
            workingDirectory: projectRoot,
            skipGitRepoCheck: true,
            // sandboxMode: see investigate() — in-VM uses
            // `danger-full-access`, local uses `workspace-write`.
            sandboxMode: pickSandboxMode(),
            approvalPolicy: "never",
            networkAccessEnabled: false,
            modelReasoningEffort: effort,
            webSearchEnabled: false,
          });
          const { events } = await thread.runStreamed(prompt, { signal });

          for await (const event of events as AsyncGenerator<ThreadEvent>) {
            switch (event.type) {
              case "thread.started":
                threadId = event.thread_id;
                break;
              case "turn.started":
                turnCount++;
                break;
              case "item.completed": {
                const prog = itemToProgress(event.item);
                if (prog) yield prog;
                if (event.item.type === "agent_message") {
                  agentMessages.push(event.item.text ?? "");
                }
                break;
              }
              case "turn.completed":
                if (event.usage) {
                  sdkMeta.usage = mapUsage(event.usage);
                  const turnCost = estimateCostUsd(model, event.usage);
                  if (turnCost !== undefined) {
                    sdkMeta.costUsd = (sdkMeta.costUsd ?? 0) + turnCost;
                  }
                }
                sdkMeta.numTurns = turnCount;
                sdkMeta.agentSessionId = threadId ?? thread.id ?? undefined;
                break;
              case "turn.failed":
                lastError = event.error?.message ?? "turn.failed";
                yield {
                  type: "error" as const,
                  message: `Codex turn failed: ${lastError.slice(0, 300)}`,
                };
                break;
              case "error":
                lastError = event.message;
                yield {
                  type: "error" as const,
                  message: `Codex stream error: ${lastError.slice(0, 300)}`,
                };
                break;
            }
          }
        } catch (err) {
          lastError = err instanceof Error ? err.message : String(err);
          yield { type: "error" as const, message: `Codex SDK error: ${lastError.slice(0, 300)}` };
        }

        if (agentMessages.length > 0) break;
        // See investigate() — read stderr first so we bail fast on quota
        // misses instead of burning all 3 attempts.
        const stderrPeek = readStderrTail(invocation.stderrLog) ?? "";
        const quotaSourceEarly =
          classifyQuotaError(lastError, "codex") || classifyQuotaError(stderrPeek, "codex");
        if (quotaSourceEarly) {
          if (stderrPeek) sdkMeta.codexStderr = stderrPeek;
          throw new QuotaExhaustedError(
            quotaSourceEarly,
            lastError || stderrPeek || "codex silent quota exit",
          );
        }
        // Silent-failure retry: gateway returned response.completed with 0
        // tokens and no agent_message — codex CLI exited clean, but no work
        // happened. Retry as if it were a transient error.
        const sawSilentFailure =
          agentMessages.length === 0 && (sdkMeta.usage?.outputTokens ?? 0) === 0;
        const shouldRetry =
          attempt < MAX_ATTEMPTS && (isTransientError(lastError) || sawSilentFailure);
        if (!shouldRetry) break;
        if (sawSilentFailure && !lastError) {
          yield {
            type: "thinking" as const,
            message: `Codex returned empty completion (likely gateway soft-fail) — retrying with backoff (attempt ${attempt}/${MAX_ATTEMPTS})`,
          };
        }
        await backoff(attempt);
      }

      const resultText = chooseFinalText(agentMessages);
      if (DEBUG) {
        yield {
          type: "thinking",
          message: `[debug] resultText: ${agentMessages.length} agent_message(s), final length=${resultText.length}, hasJson=${/```json/.test(resultText)}`,
        };
      }

      const durationMs = Date.now() - startTime;

      // Same silent-failure capture as investigate.
      const wasSilent = (sdkMeta.usage?.outputTokens ?? 0) === 0;
      const stderrTail = wasSilent ? readStderrTail(invocation.stderrLog) : undefined;
      if (wasSilent && stderrTail) {
        yield {
          type: "error" as const,
          message: `Codex silent-exit stderr: ${stderrTail.slice(0, 1500)}`,
        };
        sdkMeta.codexStderr = stderrTail;
        const quotaSourceFinal = classifyQuotaError(stderrTail, "codex");
        if (quotaSourceFinal) {
          throw new QuotaExhaustedError(quotaSourceFinal, stderrTail);
        }
      }

      const refusal = await runRefusalFollowUp(codex, threadId, projectRoot, model);
      if (refusal?.refused) {
        yield {
          type: "thinking" as const,
          message: `Refusal detected during revalidation: ${refusal.reason ?? "see raw"}`,
        };
      }

      // Empty-result throw before parse so silent failures don't crash inside
      // parseRevalidateVerdicts and bypass the cleanup in finally.
      if (!resultText) {
        const stderrSuffix = sdkMeta.codexStderr
          ? ` Stderr tail: ${sdkMeta.codexStderr.slice(0, 800)}`
          : "";
        throw new Error(
          `Codex SDK produced no revalidation result after ${MAX_ATTEMPTS} attempt(s). ` +
            `Last error: ${lastError || "(none captured)"}.${stderrSuffix}`,
        );
      }

      const verdicts = parseRevalidateVerdicts(resultText);
      if (DEBUG) {
        yield {
          type: "thinking",
          message: `[debug] parsed ${verdicts.length} verdicts`,
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
    } finally {
      cleanup();
    }
  }
}

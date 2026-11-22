import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Each startThread() call takes the next scripted event list.
const scripts: Array<Array<Record<string, unknown>>> = [];
const followUps: string[] = [];

vi.mock("@openai/codex-sdk", () => {
  class Codex {
    startThread() {
      const events = scripts.shift() ?? [];
      return {
        id: "thread-1",
        runStreamed: async () => ({
          events: (async function* () {
            for (const e of events) {
              if (e.type === "throw") throw new Error(String(e.message));
              yield e;
            }
          })(),
        }),
      };
    }
    resumeThread() {
      return {
        run: async (prompt: string) => {
          followUps.push(prompt);
          return { finalResponse: '{"refused": false}' };
        },
      };
    }
  }
  return { Codex };
});

vi.mock("../agents/shared.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../agents/shared.js")>();
  return { ...actual, backoff: async () => {} };
});

const { CodexAgentSdkPlugin, codexIncompleteTurnReason } = await import("../agents/codex-sdk.js");
const { REFUSAL_FOLLOWUP_PROMPT, ContentFilteredError } = await import("../agents/shared.js");

const FLAGGED =
  "This content was flagged for possible cybersecurity risk. If this seems wrong, try rephrasing your request.";
const batch = [
  { filePath: "a.ts", candidates: [] } as any,
  { filePath: "b.ts", candidates: [] } as any,
];
const resultsJson =
  '```json\n[{"filePath":"a.ts","findings":[]},{"filePath":"b.ts","findings":[]}]\n```';

function progressThenFailure(message: string): Array<Record<string, unknown>> {
  return [
    { type: "thread.started", thread_id: "thread-1" },
    { type: "turn.started" },
    { type: "item.completed", item: { type: "agent_message", text: "Checking the caller next." } },
    { type: "turn.failed", error: { message } },
  ];
}

function progressThenFlag(): Array<Record<string, unknown>> {
  return [
    { type: "thread.started", thread_id: "thread-1" },
    { type: "turn.started" },
    { type: "item.completed", item: { type: "command_execution", command: "cat a.ts" } },
    {
      type: "item.completed",
      item: {
        type: "agent_message",
        text: "The allowlist falls back to [] here; checking the caller next.",
      },
    },
    { type: "turn.failed", error: { message: FLAGGED } },
  ];
}

function completedTurn(): Array<Record<string, unknown>> {
  return [
    { type: "thread.started", thread_id: "thread-2" },
    { type: "turn.started" },
    { type: "item.completed", item: { type: "agent_message", text: resultsJson } },
    {
      type: "turn.completed",
      usage: { input_tokens: 10, cached_input_tokens: 0, output_tokens: 5 },
    },
  ];
}

async function drain(gen: AsyncGenerator<unknown, any>) {
  const progress: any[] = [];
  for (;;) {
    const step = await gen.next();
    if (step.done) return { progress, output: step.value };
    progress.push(step.value);
  }
}

function investigate() {
  return new CodexAgentSdkPlugin().investigate({
    batch,
    projectRoot: os.tmpdir(),
    promptTemplate: "",
    projectInfo: "",
    config: { model: "gpt-test" },
    projectId: "test",
  });
}

describe("codex investigate with an incomplete turn", () => {
  const created: string[] = [];

  beforeEach(() => {
    scripts.length = 0;
    followUps.length = 0;
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-codex-user-"));
    fs.writeFileSync(path.join(home, "auth.json"), "{}");
    created.push(home);
    vi.stubEnv("CODEX_HOME", home);
    vi.stubEnv("OPENAI_API_KEY", "");
    vi.stubEnv("ANTHROPIC_AUTH_TOKEN", "");
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    for (const dir of created.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
  });

  it("hands a content-filter block to the processor instead of parsing progress notes", async () => {
    scripts.push(progressThenFlag(), completedTurn());
    await expect(drain(investigate())).rejects.toBeInstanceOf(ContentFilteredError);
    // No same-batch retry and no JSON repair or refusal follow-up.
    expect(scripts).toHaveLength(1);
    expect(followUps).toEqual([]);
  });

  it("retries other incomplete turns on the same batch", async () => {
    scripts.push(progressThenFailure("upstream stream reset"), completedTurn());
    const { progress, output } = await drain(investigate());
    expect(output.results).toEqual([
      { filePath: "a.ts", findings: [] },
      { filePath: "b.ts", findings: [] },
    ]);
    expect(progress.some((p) => /Retrying batch/.test(p.message))).toBe(true);
    // Only the refusal check ran as a follow-up; no JSON repair of the partial turn.
    expect(followUps).toEqual([REFUSAL_FOLLOWUP_PROMPT]);
  });

  it("fails the batch when every attempt ends incomplete", async () => {
    scripts.push(
      progressThenFailure("upstream stream reset"),
      progressThenFailure("upstream stream reset"),
      progressThenFailure("upstream stream reset"),
    );
    await expect(drain(investigate())).rejects.toThrow(/did not complete after 3 attempt/);
    expect(scripts).toHaveLength(0);
  });

  it("treats a CLI exit before turn.completed as incomplete", async () => {
    const died = progressThenFlag().slice(0, -1);
    died.push({ type: "throw", message: "Codex Exec exited with code 1" });
    scripts.push(died, completedTurn());
    const { output } = await drain(investigate());
    expect(output.results).toHaveLength(2);
    expect(scripts).toHaveLength(0);
  });

  it("accepts a completed turn on the first attempt", async () => {
    scripts.push(completedTurn());
    const { output } = await drain(investigate());
    expect(output.results).toHaveLength(2);
  });
});

describe("codexIncompleteTurnReason", () => {
  it("is empty for a completed turn or a turn with no messages", () => {
    expect(
      codexIncompleteTurnReason({
        agentMessages: 2,
        turnCompleted: true,
        turnFailure: "",
        lastError: "",
      }),
    ).toBe("");
    expect(
      codexIncompleteTurnReason({
        agentMessages: 0,
        turnCompleted: false,
        turnFailure: "x",
        lastError: "",
      }),
    ).toBe("");
  });

  it("reports turn.failed even when turn.completed also arrived", () => {
    expect(
      codexIncompleteTurnReason({
        agentMessages: 1,
        turnCompleted: true,
        turnFailure: FLAGGED,
        lastError: FLAGGED,
      }),
    ).toBe(FLAGGED);
  });

  it("does not treat a recovered stream reconnect as a failure", () => {
    expect(
      codexIncompleteTurnReason({
        agentMessages: 1,
        turnCompleted: true,
        turnFailure: "",
        lastError: "Reconnecting... 1/5 (stream disconnected before completion)",
      }),
    ).toBe("");
  });
});

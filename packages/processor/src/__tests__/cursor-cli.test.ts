import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { FileRecord } from "@deepsec/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CursorCliPlugin } from "../agents/cursor-cli.js";
import type { AgentProgress } from "../agents/types.js";

// A fake `cursor-agent` that ignores its args and prints a canned
// stream-json transcript: init → a Read tool call → an assistant message
// carrying the fenced findings JSON → a result with usage. Lets us exercise
// the plugin's event parsing without a Cursor login/seat.
function writeFakeCursorAgent(dir: string, events: object[]): string {
  const bin = path.join(dir, "fake-cursor-agent");
  const jsonl = events.map((e) => JSON.stringify(e)).join("\n");
  writeFileSync(
    bin,
    `#!/usr/bin/env node\nprocess.stdout.write(${JSON.stringify(`${jsonl}\n`)});\n`,
  );
  chmodSync(bin, 0o755);
  return bin;
}

function makeRecord(filePath: string): FileRecord {
  return {
    filePath,
    projectId: "test",
    candidates: [
      { vulnSlug: "sql-injection", lineNumbers: [7], snippet: "q", matchedPattern: "concat" },
    ],
    lastScannedAt: "2026-04-01T00:00:00Z",
    lastScannedRunId: "run1",
    fileHash: "abc",
    findings: [],
    analysisHistory: [],
    status: "pending",
  };
}

async function drain(gen: AsyncGenerator<AgentProgress, { results: unknown; meta: unknown }>) {
  const progress: AgentProgress[] = [];
  let res = await gen.next();
  while (!res.done) {
    progress.push(res.value);
    res = await gen.next();
  }
  return { progress, output: res.value };
}

describe("CursorCliPlugin.investigate", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(tmpdir(), "deepsec-cursor-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
    delete process.env.CURSOR_AGENT_BIN;
  });

  it("parses findings out of the CLI's stream-json transcript", async () => {
    const findingsBlock = [
      {
        filePath: "src/auth.js",
        findings: [
          {
            severity: "CRITICAL",
            vulnSlug: "sql-injection",
            title: "SQL injection via req.query.name",
            description: "User input concatenated into a SQL string.",
            lineNumbers: [7],
            recommendation: "Use parameterized queries.",
            confidence: "high",
          },
        ],
      },
    ];
    process.env.CURSOR_AGENT_BIN = writeFakeCursorAgent(dir, [
      { type: "system", subtype: "init", session_id: "sess-1", model: "Auto" },
      {
        type: "tool_call",
        subtype: "started",
        tool_call: { readToolCall: { args: { path: "src/auth.js" } } },
      },
      {
        type: "assistant",
        message: {
          role: "assistant",
          content: [{ type: "text", text: `\`\`\`json\n${JSON.stringify(findingsBlock)}\n\`\`\`` }],
        },
      },
      {
        type: "result",
        subtype: "success",
        is_error: false,
        result: "done",
        usage: { inputTokens: 100, outputTokens: 20, cacheReadTokens: 5, cacheWriteTokens: 0 },
      },
    ]);

    const plugin = new CursorCliPlugin();
    const { progress, output } = await drain(
      plugin.investigate({
        batch: [makeRecord("src/auth.js")],
        projectRoot: dir,
        promptTemplate: "SYSTEM",
        projectInfo: "INFO",
        config: {},
      }),
    );

    const results = output.results as Array<{ filePath: string; findings: unknown[] }>;
    const auth = results.find((r) => r.filePath === "src/auth.js");
    expect(auth?.findings).toHaveLength(1);
    expect((auth?.findings[0] as { vulnSlug: string }).vulnSlug).toBe("sql-injection");

    // The Read tool call surfaced as a tool_use progress event, and the
    // session id / usage rode through into the batch meta.
    expect(progress.some((p) => p.type === "tool_use" && p.message.startsWith("Read"))).toBe(true);
    expect((output.meta as { agentSessionId?: string }).agentSessionId).toBe("sess-1");
    expect((output.meta as { usage?: { inputTokens: number } }).usage?.inputTokens).toBe(100);
  });

  it("marks files with no reported finding as clean", async () => {
    const findingsBlock = [{ filePath: "src/safe.js", findings: [] }];
    process.env.CURSOR_AGENT_BIN = writeFakeCursorAgent(dir, [
      { type: "system", subtype: "init", session_id: "sess-2", model: "Auto" },
      {
        type: "assistant",
        message: {
          role: "assistant",
          content: [{ type: "text", text: `\`\`\`json\n${JSON.stringify(findingsBlock)}\n\`\`\`` }],
        },
      },
      { type: "result", subtype: "success", is_error: false, result: "done" },
    ]);

    const plugin = new CursorCliPlugin();
    const { output } = await drain(
      plugin.investigate({
        batch: [makeRecord("src/safe.js")],
        projectRoot: dir,
        promptTemplate: "SYSTEM",
        projectInfo: "INFO",
        config: {},
      }),
    );
    const results = output.results as Array<{ filePath: string; findings: unknown[] }>;
    expect(results.find((r) => r.filePath === "src/safe.js")?.findings).toHaveLength(0);
  });
});

import type { FileRecord } from "@deepsec/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { createMock, listMock } = vi.hoisted(() => ({
  createMock: vi.fn(),
  listMock: vi.fn(),
}));

vi.mock("@cursor/sdk", () => {
  class CursorAgentError extends Error {
    readonly isRetryable: boolean;

    constructor(message: string, options?: { isRetryable?: boolean }) {
      super(message);
      this.name = "CursorAgentError";
      this.isRetryable = options?.isRetryable ?? false;
    }
  }

  return {
    Agent: {
      create: createMock,
    },
    Cursor: {
      models: {
        list: listMock,
      },
    },
    CursorAgentError,
  };
});

import { __resetCursorModelCatalogCacheForTests } from "../agents/cursor-model.js";
import { CursorAgentSdkPlugin } from "../agents/cursor-sdk.js";

function makeRecord(filePath: string): FileRecord {
  return {
    filePath,
    projectId: "proj",
    candidates: [
      {
        vulnSlug: "auth-bypass",
        lineNumbers: [12],
        snippet: "dangerous()",
        matchedPattern: "dangerous",
      },
    ],
    lastScannedAt: new Date().toISOString(),
    lastScannedRunId: "scan-1",
    fileHash: "hash",
    findings: [],
    analysisHistory: [],
    status: "pending",
  };
}

async function collectGenerator<TProgress, TResult>(gen: AsyncGenerator<TProgress, TResult>) {
  const events: TProgress[] = [];
  let next = await gen.next();
  while (!next.done) {
    events.push(next.value);
    next = await gen.next();
  }
  return { events, result: next.value };
}

function makeRun(resultText: string, messages: unknown[] = []) {
  return {
    id: "run-1",
    stream: async function* () {
      for (const message of messages) yield message;
    },
    wait: vi.fn().mockResolvedValue({
      id: "run-1",
      status: "finished",
      result: resultText,
      durationMs: 321,
    }),
  };
}

function makeAgent(params: {
  mainResult: string;
  followUpResult?: string;
  messages?: unknown[];
}) {
  const asyncDispose = vi.fn().mockResolvedValue(undefined);
  const send = vi
    .fn()
    .mockResolvedValueOnce(makeRun(params.mainResult, params.messages))
    .mockResolvedValueOnce(
      makeRun(params.followUpResult ?? '{"refused": false, "skipped": []}'),
    );
  return {
    agentId: "cursor-agent-1",
    send,
    close: vi.fn(),
    reload: vi.fn(),
    [Symbol.asyncDispose]: asyncDispose,
  };
}

const cursorCatalog = [
  {
    id: "composer-2.5",
    displayName: "Composer 2.5",
    aliases: ["composer"],
    parameters: [
      {
        id: "fast",
        displayName: "Fast",
        values: [{ value: "false" }, { value: "true", displayName: "Fast" }],
      },
    ],
    variants: [
      {
        params: [{ id: "fast", value: "true" }],
        displayName: "Composer 2.5",
        isDefault: true,
      },
      {
        params: [{ id: "fast", value: "false" }],
        displayName: "Composer 2.5",
      },
    ],
  },
  {
    id: "gpt-5.4",
    displayName: "GPT-5.4",
    parameters: [
      {
        id: "context",
        displayName: "Context",
        values: [
          { value: "272k", displayName: "272K" },
          { value: "1m", displayName: "1M" },
        ],
      },
      {
        id: "reasoning",
        displayName: "Reasoning",
        values: [
          { value: "medium", displayName: "Medium" },
          { value: "high", displayName: "High" },
        ],
      },
      {
        id: "fast",
        displayName: "Fast",
        values: [{ value: "false" }, { value: "true", displayName: "Fast" }],
      },
    ],
    variants: [
      {
        params: [
          { id: "context", value: "1m" },
          { id: "reasoning", value: "medium" },
          { id: "fast", value: "false" },
        ],
        displayName: "GPT-5.4",
        isDefault: true,
      },
      {
        params: [
          { id: "context", value: "272k" },
          { id: "reasoning", value: "high" },
          { id: "fast", value: "false" },
        ],
        displayName: "GPT-5.4",
      },
    ],
  },
];

describe("CursorAgentSdkPlugin", () => {
  let prevCursorApiKey: string | undefined;

  beforeEach(() => {
    prevCursorApiKey = process.env.CURSOR_API_KEY;
    delete process.env.CURSOR_API_KEY;
    createMock.mockReset();
    listMock.mockReset();
    listMock.mockResolvedValue(cursorCatalog);
    __resetCursorModelCatalogCacheForTests();
  });

  afterEach(() => {
    if (prevCursorApiKey === undefined) delete process.env.CURSOR_API_KEY;
    else process.env.CURSOR_API_KEY = prevCursorApiKey;
    __resetCursorModelCatalogCacheForTests();
  });

  it("investigate() uses composer-2.5 by default and parses findings", async () => {
    const agent = makeAgent({
      mainResult: `\`\`\`json
[
  {
    "filePath": "src/app.ts",
    "findings": [
      {
        "severity": "HIGH",
        "vulnSlug": "auth-bypass",
        "title": "missing auth",
        "description": "route is unprotected",
        "lineNumbers": [12],
        "recommendation": "add auth",
        "confidence": "high"
      }
    ]
  }
]
\`\`\``,
      messages: [
        { type: "thinking", agent_id: "a", run_id: "r", text: "Reading target files" },
        {
          type: "tool_call",
          agent_id: "a",
          run_id: "r",
          call_id: "c1",
          name: "ReadFile",
          status: "completed",
          args: { path: "src/app.ts" },
        },
      ],
    });
    createMock.mockResolvedValue(agent);

    const plugin = new CursorAgentSdkPlugin();
    const { events, result } = await collectGenerator(
      plugin.investigate({
        batch: [makeRecord("src/app.ts")],
        projectRoot: "/repo",
        promptTemplate: "Investigate carefully.",
        projectInfo: "",
        config: {},
      }),
    );

    expect(createMock).toHaveBeenCalledWith(
      expect.objectContaining({
        apiKey: undefined,
        mode: "plan",
        model: { id: "composer-2.5", params: [{ id: "fast", value: "false" }] },
        local: expect.objectContaining({ cwd: "/repo" }),
      }),
    );
    expect(agent.send).toHaveBeenNthCalledWith(
      1,
      expect.stringContaining("Do not use `CreatePlan` or any planning tool."),
      expect.objectContaining({
        mode: "plan",
        model: { id: "composer-2.5", params: [{ id: "fast", value: "false" }] },
      }),
    );
    expect(result.results).toHaveLength(1);
    expect(result.results[0].filePath).toBe("src/app.ts");
    expect(result.results[0].findings[0].title).toBe("missing auth");
    expect(result.meta.agentSessionId).toBe("cursor-agent-1");
    expect(events.some((event) => (event as { type: string }).type === "tool_use")).toBe(true);
    expect(agent[Symbol.asyncDispose]).toHaveBeenCalled();
  });

  it("revalidate() resolves combined Cursor option slugs and parses verdicts", async () => {
    const agent = makeAgent({
      mainResult: `\`\`\`json
[
  {
    "filePath": "src/app.ts",
    "title": "missing auth",
    "verdict": "true-positive",
    "reasoning": "request reaches the handler without auth middleware"
  }
]
\`\`\``,
    });
    createMock.mockResolvedValue(agent);

    const plugin = new CursorAgentSdkPlugin();
    const { result } = await collectGenerator(
      plugin.revalidate({
        batch: [
          {
            ...makeRecord("src/app.ts"),
            status: "analyzed",
            findings: [
              {
                severity: "HIGH",
                vulnSlug: "auth-bypass",
                title: "missing auth",
                description: "route is unprotected",
                lineNumbers: [12],
                recommendation: "add auth",
                confidence: "high",
              },
            ],
          },
        ],
        projectRoot: "/repo",
        projectInfo: "API service",
        config: { model: "gpt-5.4-high-1m" },
      }),
    );

    expect(createMock).toHaveBeenCalledWith(
      expect.objectContaining({
        model: {
          id: "gpt-5.4",
          params: [
            { id: "context", value: "1m" },
            { id: "reasoning", value: "high" },
            { id: "fast", value: "false" },
          ],
        },
      }),
    );
    expect(agent.send).toHaveBeenNthCalledWith(
      1,
      expect.any(String),
      expect.objectContaining({
        model: {
          id: "gpt-5.4",
          params: [
            { id: "context", value: "1m" },
            { id: "reasoning", value: "high" },
            { id: "fast", value: "false" },
          ],
        },
      }),
    );
    expect(result.verdicts).toHaveLength(1);
    expect(result.verdicts[0].verdict).toBe("true-positive");
    expect(result.meta.agentSessionId).toBe("cursor-agent-1");
  });
});

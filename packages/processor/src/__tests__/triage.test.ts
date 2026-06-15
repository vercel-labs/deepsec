import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { FileRecord } from "@deepsec/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { queryMock, promptMock, listMock } = vi.hoisted(() => ({
  queryMock: vi.fn(),
  promptMock: vi.fn(),
  listMock: vi.fn(),
}));

vi.mock("@anthropic-ai/claude-agent-sdk", () => ({
  query: queryMock,
}));

vi.mock("@cursor/sdk", () => ({
  Agent: {
    prompt: promptMock,
  },
  Cursor: {
    models: {
      list: listMock,
    },
  },
}));

import { __resetCursorModelCatalogCacheForTests } from "../agents/cursor-model.js";
import { triage } from "../triage.js";

interface Fixture {
  tmp: string;
  targetRoot: string;
  projectId: string;
  dataRoot: string;
  readRecord: (relPath: string) => FileRecord;
}

function setupProject(): Fixture {
  const projectId = "triage-proj";
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-triage-"));
  const targetRoot = path.join(tmp, "target");
  const dataRoot = path.join(tmp, "data");
  fs.mkdirSync(path.join(dataRoot, projectId, "files", "src"), { recursive: true });
  fs.mkdirSync(path.join(targetRoot, "src"), { recursive: true });
  fs.writeFileSync(path.join(targetRoot, "src/app.ts"), "// test file\n");
  fs.writeFileSync(
    path.join(dataRoot, projectId, "project.json"),
    JSON.stringify({
      projectId,
      rootPath: targetRoot,
      createdAt: new Date().toISOString(),
    }),
  );
  fs.writeFileSync(path.join(dataRoot, projectId, "INFO.md"), "Auth-sensitive service.");
  const record: FileRecord = {
    filePath: "src/app.ts",
    projectId,
    candidates: [],
    lastScannedAt: new Date().toISOString(),
    lastScannedRunId: "scan-1",
    fileHash: "hash",
    findings: [
      {
        severity: "MEDIUM",
        vulnSlug: "auth-bypass",
        title: "missing auth check",
        description: "route is reachable without auth",
        lineNumbers: [10],
        recommendation: "add auth middleware",
        confidence: "high",
      },
    ],
    analysisHistory: [],
    status: "analyzed",
  };
  fs.writeFileSync(
    path.join(dataRoot, projectId, "files", "src", "app.ts.json"),
    JSON.stringify(record),
  );
  process.env.DEEPSEC_DATA_ROOT = dataRoot;
  return {
    tmp,
    targetRoot,
    projectId,
    dataRoot,
    readRecord(relPath: string) {
      return JSON.parse(
        fs.readFileSync(path.join(dataRoot, projectId, "files", `${relPath}.json`), "utf-8"),
      );
    },
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

describe("triage", () => {
  let prevDataRoot: string | undefined;

  beforeEach(() => {
    prevDataRoot = process.env.DEEPSEC_DATA_ROOT;
    queryMock.mockReset();
    promptMock.mockReset();
    listMock.mockReset();
    listMock.mockResolvedValue(cursorCatalog);
    __resetCursorModelCatalogCacheForTests();
  });

  afterEach(() => {
    if (prevDataRoot === undefined) delete process.env.DEEPSEC_DATA_ROOT;
    else process.env.DEEPSEC_DATA_ROOT = prevDataRoot;
    __resetCursorModelCatalogCacheForTests();
  });

  it("supports the cursor backend", async () => {
    const fx = setupProject();
    promptMock.mockResolvedValue({
      status: "finished",
      result: `\`\`\`json
[
  {
    "title": "missing auth check",
    "priority": "P1",
    "exploitability": "moderate",
    "impact": "high",
    "reasoning": "Auth is missing but exploitation still depends on route reachability."
  }
]
\`\`\``,
    });

    const result = await triage({
      projectId: fx.projectId,
      severity: "MEDIUM",
      agentType: "cursor",
    });

    expect(promptMock).toHaveBeenCalledWith(
      expect.stringContaining("Do not use `CreatePlan` or any planning tool."),
      expect.objectContaining({
        mode: "plan",
        model: { id: "composer-2.5", params: [{ id: "fast", value: "false" }] },
        local: expect.objectContaining({ cwd: fx.targetRoot }),
      }),
    );
    expect(result.triaged).toBe(1);
    expect(result.p1).toBe(1);
    const record = fx.readRecord("src/app.ts");
    expect(record.findings[0].triage?.priority).toBe("P1");
    expect(record.findings[0].triage?.model).toBe("composer-2.5");
    fs.rmSync(fx.tmp, { recursive: true, force: true });
  });

  it("resolves combined Cursor option slugs for the cursor backend", async () => {
    const fx = setupProject();
    promptMock.mockResolvedValue({
      status: "finished",
      result: `\`\`\`json
[
  {
    "title": "missing auth check",
    "priority": "P1",
    "exploitability": "moderate",
    "impact": "high",
    "reasoning": "Auth is missing but exploitation still depends on route reachability."
  }
]
\`\`\``,
    });

    const result = await triage({
      projectId: fx.projectId,
      severity: "MEDIUM",
      agentType: "cursor",
      model: "gpt-5.4-high-1m",
    });

    expect(promptMock).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({
        mode: "plan",
        model: {
          id: "gpt-5.4",
          params: [
            { id: "context", value: "1m" },
            { id: "reasoning", value: "high" },
            { id: "fast", value: "false" },
          ],
        },
        local: expect.objectContaining({ cwd: fx.targetRoot }),
      }),
    );
    expect(result.triaged).toBe(1);
    const record = fx.readRecord("src/app.ts");
    expect(record.findings[0].triage?.model).toBe("gpt-5.4-high-1m");
    fs.rmSync(fx.tmp, { recursive: true, force: true });
  });

  it("keeps the existing claude path as the default", async () => {
    const fx = setupProject();
    queryMock.mockImplementation(async function* () {
      yield {
        type: "result",
        subtype: "success",
        result: `\`\`\`json
[
  {
    "title": "missing auth check",
    "priority": "P0",
    "exploitability": "trivial",
    "impact": "critical",
    "reasoning": "The finding is externally reachable and immediately exploitable."
  }
]
\`\`\``,
      };
    });

    const result = await triage({
      projectId: fx.projectId,
      severity: "MEDIUM",
    });

    expect(queryMock).toHaveBeenCalledTimes(1);
    expect(promptMock).not.toHaveBeenCalled();
    expect(result.triaged).toBe(1);
    expect(result.p0).toBe(1);
    const record = fx.readRecord("src/app.ts");
    expect(record.findings[0].triage?.priority).toBe("P0");
    expect(record.findings[0].triage?.model).toBe("claude-sonnet-4-6");
    fs.rmSync(fx.tmp, { recursive: true, force: true });
  });
});

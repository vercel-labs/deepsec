import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { type FileRecord, readFileRecord, writeFileRecord } from "@deepsec/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { releaseUnfinished, streamLogsCapped } from "../sandbox/orchestrator.js";

/** A command whose log stream replays from the start and closes after `cuts[i]` chunks. */
function replayingCommand(chunks: string[], cuts: number[]) {
  let call = 0;
  return {
    calls: () => call,
    logs() {
      const limit = cuts[call++] ?? chunks.length;
      return (async function* () {
        for (const data of chunks.slice(0, limit)) yield { stream: "stdout", data };
      })();
    },
  };
}

describe("streamLogsCapped reconnects", () => {
  it("emits each line once when the stream closes early and replays", async () => {
    const chunks = ["one\ntw", "o\nthree\n", "four\nfive\n"];
    const cmd = replayingCommand(chunks, [2, 3]);
    let checks = 0;
    const lines: string[] = [];
    await streamLogsCapped(
      cmd,
      "[s]",
      (m) => lines.push(m),
      undefined,
      async () => ++checks > 1,
    );
    expect(lines.filter((l) => !l.includes("reconnecting"))).toEqual([
      "[s] one",
      "[s] two",
      "[s] three",
      "[s] four",
      "[s] five",
    ]);
    expect(cmd.calls()).toBe(2);
  });

  it("does not reconnect once the command has finished", async () => {
    const cmd = replayingCommand(["a\n"], [1]);
    await streamLogsCapped(
      cmd,
      "[s]",
      () => {},
      undefined,
      async () => true,
    );
    expect(cmd.calls()).toBe(1);
  });

  it("makes a single pass without an isFinished check", async () => {
    const cmd = replayingCommand(["a\n", "b\n"], [1]);
    const lines: string[] = [];
    await streamLogsCapped(cmd, "[s]", (m) => lines.push(m));
    expect(lines).toEqual(["[s] a"]);
    expect(cmd.calls()).toBe(1);
  });
});

describe("releaseUnfinished", () => {
  let prev: string | undefined;
  let tmp: string;

  beforeEach(() => {
    prev = process.env.DEEPSEC_DATA_ROOT;
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-release-"));
    process.env.DEEPSEC_DATA_ROOT = tmp;
  });

  afterEach(() => {
    if (prev === undefined) delete process.env.DEEPSEC_DATA_ROOT;
    else process.env.DEEPSEC_DATA_ROOT = prev;
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  function record(filePath: string, status: FileRecord["status"]): FileRecord {
    return {
      filePath,
      projectId: "p",
      candidates: [],
      lastScannedAt: new Date(0).toISOString(),
      lastScannedRunId: "scan",
      fileHash: "h",
      findings: [],
      analysisHistory: [],
      status,
      ...(status === "processing"
        ? { lockedByRunId: "sandbox-run", lockedAt: new Date(0).toISOString() }
        : {}),
    };
  }

  it("marks the worker's still-processing files as error and leaves the rest alone", () => {
    writeFileRecord(record("a.ts", "processing"));
    writeFileRecord(record("b.ts", "analyzed"));
    const logs: string[] = [];
    releaseUnfinished({ manifest: ["a.ts", "b.ts", "missing.ts"], index: 3 }, "p", (m) =>
      logs.push(m),
    );
    const a = readFileRecord("p", "a.ts");
    expect(a?.status).toBe("error");
    expect(a?.lockedByRunId).toBeUndefined();
    expect(readFileRecord("p", "b.ts")?.status).toBe("analyzed");
    expect(logs).toEqual(["[sandbox-3] 1 file(s) did not finish; marked error for the next run"]);
  });
});

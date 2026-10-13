import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fileRecordPath } from "../paths.js";
import {
  createRunMeta,
  ensureProject,
  generateRunId,
  isPidAlive,
  loadAllFileRecords,
  readFileRecord,
} from "../run.js";

describe("generateRunId", () => {
  it("returns a string with timestamp and suffix", () => {
    const id = generateRunId();
    expect(id).toMatch(/^\d{14}-[a-f0-9]{16}$/);
  });

  it("generates unique IDs", () => {
    const ids = new Set(Array.from({ length: 20 }, () => generateRunId()));
    expect(ids.size).toBe(20);
  });
});

describe("createRunMeta", () => {
  it("creates a scan RunMeta", () => {
    const meta = createRunMeta({
      projectId: "test-project",
      rootPath: "/tmp/test",
      type: "scan",
      scannerConfig: { matcherSlugs: ["xss", "rce"] },
    });

    expect(meta.projectId).toBe("test-project");
    expect(meta.type).toBe("scan");
    expect(meta.phase).toBe("running");
    expect(meta.scannerConfig?.matcherSlugs).toEqual(["xss", "rce"]);
    expect(meta.stats).toEqual({});
    expect(meta.runId).toMatch(/^\d{14}-[a-f0-9]{16}$/);
  });

  it("creates a process RunMeta", () => {
    const meta = createRunMeta({
      projectId: "test",
      rootPath: "/tmp",
      type: "process",
      processorConfig: {
        agentType: "claude-agent-sdk",
        model: "claude-opus-4-6",
        modelConfig: {},
      },
    });

    expect(meta.type).toBe("process");
    expect(meta.processorConfig?.agentType).toBe("claude-agent-sdk");
  });

  it("captures pid and hostname for crash recovery", () => {
    const meta = createRunMeta({
      projectId: "test",
      rootPath: "/tmp",
      type: "process",
    });
    expect(meta.pid).toBe(process.pid);
    expect(meta.hostname).toBe(os.hostname());
  });
});

describe("isPidAlive", () => {
  it("returns true for the current process", () => {
    expect(isPidAlive(process.pid)).toBe(true);
  });

  it("returns false for a PID that does not exist", () => {
    // PID 0x7fffffff is well outside the kernel's pid_max on every
    // platform we run on, so the kernel can't possibly be tracking a
    // live process at that number — process.kill(pid, 0) gives ESRCH.
    expect(isPidAlive(0x7fffffff)).toBe(false);
  });
});

describe("readFileRecord / loadAllFileRecords — per-finding salvage", () => {
  const projectId = "salvage-test";
  let tmp: string;
  let oldDataRoot: string | undefined;
  let warnSpy: ReturnType<typeof vi.spyOn>;

  const validFinding = {
    severity: "HIGH",
    vulnSlug: "xss",
    title: "Valid finding",
    description: "d",
    lineNumbers: [1],
    recommendation: "r",
    confidence: "high",
  };

  function writeRawRecord(filePath: string, findings: unknown[], extra: object = {}): void {
    const p = fileRecordPath(projectId, filePath);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(
      p,
      JSON.stringify({
        filePath,
        projectId,
        candidates: [],
        lastScannedAt: "2026-04-01T14:30:52.000Z",
        lastScannedRunId: "run1",
        fileHash: "abc",
        findings,
        analysisHistory: [],
        status: "analyzed",
        ...extra,
      }),
    );
  }

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-salvage-"));
    oldDataRoot = process.env.DEEPSEC_DATA_ROOT;
    process.env.DEEPSEC_DATA_ROOT = tmp;
    warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
  });

  afterEach(() => {
    warnSpy.mockRestore();
    if (oldDataRoot === undefined) delete process.env.DEEPSEC_DATA_ROOT;
    else process.env.DEEPSEC_DATA_ROOT = oldDataRoot;
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it("keeps valid findings when a sibling finding is malformed, and warns", () => {
    // Regression: one malformed field in one finding used to fail the
    // whole record's parse inside a silent catch — the file's valid
    // findings vanished with no error (148 findings across one observed
    // 12-run comparison).
    writeRawRecord("src/a.ts", [
      validFinding,
      { ...validFinding, title: "Bad", severity: "INFORMATIONAL" },
    ]);

    const rec = readFileRecord(projectId, "src/a.ts");

    expect(rec?.findings.map((f) => f.title)).toEqual(["Valid finding"]);
    expect(warnSpy.mock.calls.join("\n")).toContain("malformed finding");
  });

  it("returns null and warns when the record envelope is invalid", () => {
    writeRawRecord("src/a.ts", [validFinding], { status: "nope" });
    expect(readFileRecord(projectId, "src/a.ts")).toBeNull();
    expect(warnSpy.mock.calls.join("\n")).toContain("invalid file record");
  });

  it("returns null and warns on unparseable JSON", () => {
    const p = fileRecordPath(projectId, "src/a.ts");
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, "{not json");
    expect(readFileRecord(projectId, "src/a.ts")).toBeNull();
    expect(warnSpy.mock.calls.join("\n")).toContain("unreadable file record");
  });

  it("loadAllFileRecords salvages per finding instead of skipping the file", () => {
    writeRawRecord("src/a.ts", [
      validFinding,
      { ...validFinding, title: "Bad", lineNumbers: ["1"] },
    ]);
    writeRawRecord("src/b.ts", [validFinding]);

    const records = loadAllFileRecords(projectId);

    expect(records).toHaveLength(2);
    const a = records.find((r) => r.filePath === "src/a.ts");
    expect(a?.findings.map((f) => f.title)).toEqual(["Valid finding"]);
    expect(warnSpy.mock.calls.join("\n")).toContain("malformed finding");
  });
});

describe("ensureProject", () => {
  it("repairs a truncated generated project registration atomically", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-repair-project-"));
    const oldDataRoot = process.env.DEEPSEC_DATA_ROOT;
    process.env.DEEPSEC_DATA_ROOT = path.join(tmp, "data");
    const root = path.join(tmp, "project");
    fs.mkdirSync(root);
    const configDir = path.join(process.env.DEEPSEC_DATA_ROOT, "test-project");
    fs.mkdirSync(configDir, { recursive: true });
    fs.writeFileSync(path.join(configDir, "project.json"), '{"projectId":');

    try {
      const project = ensureProject("test-project", root);
      expect(project.rootPath).toBe(path.resolve(root));
      expect(
        JSON.parse(fs.readFileSync(path.join(configDir, "project.json"), "utf8")),
      ).toMatchObject({ projectId: "test-project", rootPath: path.resolve(root) });
      expect(fs.readdirSync(configDir).filter((name) => name.endsWith(".tmp"))).toEqual([]);
    } finally {
      if (oldDataRoot === undefined) delete process.env.DEEPSEC_DATA_ROOT;
      else process.env.DEEPSEC_DATA_ROOT = oldDataRoot;
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("does not print git errors for non-git roots", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-ensure-project-"));
    const oldDataRoot = process.env.DEEPSEC_DATA_ROOT;
    process.env.DEEPSEC_DATA_ROOT = path.join(tmp, "data");
    const root = path.join(tmp, "project");
    fs.mkdirSync(root);

    const writeSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    try {
      const project = ensureProject("test-project", root);
      expect(project.githubUrl).toBeUndefined();
      expect(writeSpy.mock.calls.join("")).not.toContain("fatal: not a git repository");
    } finally {
      writeSpy.mockRestore();
      if (oldDataRoot === undefined) {
        delete process.env.DEEPSEC_DATA_ROOT;
      } else {
        process.env.DEEPSEC_DATA_ROOT = oldDataRoot;
      }
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

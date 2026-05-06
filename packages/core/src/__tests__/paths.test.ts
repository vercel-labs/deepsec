import path from "node:path";
import { describe, expect, it } from "vitest";
import { dataDir, fileRecordPath, filesDir, runMetaPath, runsDir } from "../paths.js";

describe("paths", () => {
  // path.join uses native separators (\\ on Windows, / elsewhere). Build
  // expected values with path.join so the asserts hold on every platform.
  it("filesDir follows convention", () => {
    expect(filesDir("myapp")).toBe(path.join("data", "myapp", "files"));
  });

  it("fileRecordPath follows convention", () => {
    expect(fileRecordPath("myapp", "src/api/users.ts")).toBe(
      path.join("data", "myapp", "files", "src", "api", "users.ts.json"),
    );
  });

  it("runsDir follows convention", () => {
    expect(runsDir("myapp")).toBe(path.join("data", "myapp", "runs"));
  });

  it("runMetaPath is flat file", () => {
    expect(runMetaPath("myapp", "run1")).toBe(path.join("data", "myapp", "runs", "run1.json"));
  });

  // Path-traversal protection — any segment that could escape the per-project
  // mirror (`..`, absolute paths, separators, null bytes) must throw, since
  // these are the documented sandbox-round-trip and CLI-flag attack vectors.
  describe("path traversal", () => {
    it("dataDir rejects '..' projectId", () => {
      expect(() => dataDir("..")).toThrow(/Invalid projectId/);
    });

    it("dataDir rejects projectId with slash", () => {
      expect(() => dataDir("../escape")).toThrow(/Invalid projectId/);
    });

    it("dataDir rejects absolute projectId", () => {
      expect(() => dataDir("/etc/passwd")).toThrow(/Invalid projectId/);
    });

    it("dataDir rejects null byte", () => {
      expect(() => dataDir("foo\0bar")).toThrow(/null byte/);
    });

    it("fileRecordPath rejects '..' segment in filePath", () => {
      expect(() => fileRecordPath("myapp", "../../tmp/evil")).toThrow(/Invalid filePath/);
    });

    it("fileRecordPath rejects absolute filePath", () => {
      expect(() => fileRecordPath("myapp", "/etc/passwd")).toThrow(/Invalid filePath/);
    });

    it("runMetaPath rejects runId with separator", () => {
      expect(() => runMetaPath("myapp", "../escape")).toThrow(/Invalid runId/);
    });
  });
});

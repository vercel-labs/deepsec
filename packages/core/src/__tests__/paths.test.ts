import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { defineConfig, setLoadedConfig } from "../config.js";
import { dataDir, fileRecordPath, filesDir, getDataRoot, runMetaPath, runsDir } from "../paths.js";

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
  describe("getDataRoot", () => {
    afterEach(() => {
      delete process.env.DEEPSEC_DATA_ROOT;
      setLoadedConfig(defineConfig({ projects: [] }));
    });

    it("defaults to 'data'", () => {
      expect(getDataRoot()).toBe("data");
    });

    it("respects DEEPSEC_DATA_ROOT env var", () => {
      process.env.DEEPSEC_DATA_ROOT = "/custom/data";
      expect(getDataRoot()).toBe("/custom/data");
    });

    it("respects config dataDir when env var is absent", () => {
      setLoadedConfig(defineConfig({ projects: [], dataDir: "/cfg/data" }));
      expect(getDataRoot()).toBe("/cfg/data");
    });

    it("prefers env var over config dataDir", () => {
      process.env.DEEPSEC_DATA_ROOT = "/env/data";
      setLoadedConfig(defineConfig({ projects: [], dataDir: "/cfg/data" }));
      expect(getDataRoot()).toBe("/env/data");
    });
  });

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

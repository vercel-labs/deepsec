import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { MatcherPlugin } from "@deepsec/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mock glob before importing the scanner so the driver picks up the mock.
vi.mock("glob", () => ({
  glob: vi.fn(),
}));

const { glob } = await import("glob");
const { RegexScannerDriver } = await import("../index.js");

describe("RegexScannerDriver — Windows path normalization", () => {
  let tmpRoot: string;
  let dataRoot: string;

  beforeEach(() => {
    tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-scan-"));
    dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-data-"));
    process.env.DEEPSEC_DATA_ROOT = dataRoot;

    fs.mkdirSync(path.join(tmpRoot, "src", "api"), { recursive: true });
    fs.writeFileSync(path.join(tmpRoot, "src", "api", "foo.ts"), "eval(userInput);\n");
  });

  afterEach(() => {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
    fs.rmSync(dataRoot, { recursive: true, force: true });
    delete process.env.DEEPSEC_DATA_ROOT;
    vi.clearAllMocks();
  });

  it("normalizes backslash-separated glob output to POSIX before record write", async () => {
    // Simulate Windows glob output (backslash separators).
    vi.mocked(glob).mockResolvedValueOnce(["src\\api\\foo.ts"] as never);

    const matcher: MatcherPlugin = {
      slug: "test-eval",
      noiseTier: "normal",
      description: "test matcher",
      filePatterns: ["**/*.ts"],
      match(content) {
        return /eval\s*\(/.test(content)
          ? [
              {
                vulnSlug: "test-eval",
                lineNumbers: [1],
                snippet: content,
                matchedPattern: "eval",
              },
            ]
          : [];
      },
    };

    const driver = new RegexScannerDriver();
    const gen = driver.scan({
      root: tmpRoot,
      matchers: [matcher],
      projectId: "winproj",
      runId: "run-1",
    });

    let result = await gen.next();
    while (!result.done) result = await gen.next();
    const records = result.value;

    expect(records).toHaveLength(1);
    expect(records[0].filePath).toBe("src/api/foo.ts");

    // The record should land on disk under the POSIX-normalized path.
    const recordPath = path.join(dataRoot, "winproj", "files", "src", "api", "foo.ts.json");
    expect(fs.existsSync(recordPath)).toBe(true);
  });
});

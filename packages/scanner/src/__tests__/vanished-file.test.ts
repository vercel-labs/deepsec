import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { MatcherPlugin } from "@deepsec/core";
import { expect, it } from "vitest";
import { RegexScannerDriver } from "../index.js";

it("continues scanning when a matched file disappears after it is read", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-source-"));
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-data-"));
  const previousDataRoot = process.env.DEEPSEC_DATA_ROOT;
  process.env.DEEPSEC_DATA_ROOT = dataRoot;

  try {
    const sourceFile = path.join(root, "sample.ts");
    fs.writeFileSync(sourceFile, "eval(input);\n");
    let matcherCalled = false;

    const matcher: MatcherPlugin = {
      slug: "vanished-file-test",
      noiseTier: "normal",
      description: "test matcher",
      filePatterns: ["**/*.ts"],
      match(content) {
        matcherCalled = true;
        fs.unlinkSync(sourceFile);
        return [
          {
            vulnSlug: "vanished-file-test",
            lineNumbers: [1],
            snippet: content,
            matchedPattern: "eval",
          },
        ];
      },
    };

    const generator = new RegexScannerDriver().scan({
      root,
      matchers: [matcher],
      projectId: "vanished-file-test",
      runId: "run-1",
    });
    let result = await generator.next();
    while (!result.done) result = await generator.next();

    expect(matcherCalled).toBe(true);
    expect(fs.existsSync(sourceFile)).toBe(false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(dataRoot, { recursive: true, force: true });
    if (previousDataRoot === undefined) delete process.env.DEEPSEC_DATA_ROOT;
    else process.env.DEEPSEC_DATA_ROOT = previousDataRoot;
  }
});

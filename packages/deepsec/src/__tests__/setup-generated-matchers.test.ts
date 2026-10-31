import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { DeclarativeMatcherSpec } from "@deepsec/scanner";
import { describe, expect, it } from "vitest";
import { readGeneratedMatchers, writeGeneratedMatchers } from "../setup/generated-matchers.js";

function spec(slug: string): DeclarativeMatcherSpec {
  return {
    version: 1,
    slug,
    description: `${slug} matcher`,
    noiseTier: "precise",
    filePatterns: ["**/*.ts"],
    patterns: [{ source: "export", label: "export" }],
    examples: ["export const value = 1"],
    closesSurfaceIds: ["api"],
  };
}

describe("generated matcher persistence", () => {
  it("reads previous specs so a resumed generation pass can append", () => {
    const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-matchers-"));
    writeGeneratedMatchers(workspace, [spec("existing-route")]);
    const existing = readGeneratedMatchers(workspace);
    writeGeneratedMatchers(workspace, [
      ...existing.map((matcher) => matcher.declarativeSpec),
      spec("new-route"),
    ]);

    expect(readGeneratedMatchers(workspace).map((matcher) => matcher.slug)).toEqual([
      "existing-route",
      "new-route",
    ]);
  });
});

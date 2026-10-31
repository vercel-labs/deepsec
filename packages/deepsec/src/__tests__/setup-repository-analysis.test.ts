import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { parseRepositoryAnalysis } from "../setup/repository-analysis.js";

describe("repository analysis parsing", () => {
  it("accepts legitimate angle-bracket syntax in a completed threat model", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-analysis-angles-"));
    fs.writeFileSync(path.join(root, "README.md"), "# app\n");
    const infoMarkdown = [
      "# app",
      "## What this codebase does",
      "TypeScript app using Promise<void>.",
      "## Auth shape",
      "Session.",
      "## Threat model",
      "Untrusted <script> payloads can reach rendering.",
      "## Project-specific patterns to flag",
      "Routes.",
      "## Known false-positives",
      "None.",
    ].join("\n");
    const result = parseRepositoryAnalysis(
      JSON.stringify({
        infoMarkdown,
        surfaces: [
          {
            id: "ui",
            kind: "http",
            description: "UI",
            fileGlobs: ["README.md"],
            representativeFiles: ["README.md"],
            exposure: "public",
          },
        ],
        inspectedPaths: ["README.md"],
      }),
      root,
    );
    expect(result.infoMarkdown).toContain("<script>");
  });
  it("defers stale representative-file existence checks to inventory grounding", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-analysis-"));
    fs.writeFileSync(path.join(root, "README.md"), "# app\n");
    const infoMarkdown = [
      "# app",
      "## What this codebase does",
      "App.",
      "## Auth shape",
      "Session.",
      "## Threat model",
      "Public input.",
      "## Project-specific patterns to flag",
      "Routes.",
      "## Known false-positives",
      "None.",
    ].join("\n");

    const result = parseRepositoryAnalysis(
      JSON.stringify({
        infoMarkdown,
        surfaces: [
          {
            id: "api-routes",
            kind: "http",
            description: "API routes",
            fileGlobs: ["src/routes/**/*.ts"],
            representativeFiles: ["src/routes/removed.ts"],
            exposure: "public",
          },
        ],
        inspectedPaths: ["README.md"],
      }),
      root,
    );

    expect(result.surfaces[0]?.representativeFiles).toEqual(["src/routes/removed.ts"]);
  });
});

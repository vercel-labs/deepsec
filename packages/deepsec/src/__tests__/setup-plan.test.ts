import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { buildSetupPlan } from "../setup/plan.js";

describe("headless setup plan", () => {
  it("is read-only and reports missing identity inputs", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-plan-"));
    fs.writeFileSync(path.join(root, "index.ts"), "export const value = 1;\n");
    const workspace = path.join(root, ".deepsec");

    const plan = await buildSetupPlan({
      workspaceDir: workspace,
      projectRoot: root,
      projectId: "app",
      model: "gpt-5.6-sol",
      agent: "codex",
      deterministicProjectName: "deepsec-app-abcd1234",
      env: {},
      runCli: async () => ({ exitCode: 1, stdout: "", stderr: "" }),
    });

    expect(plan.type).toBe("plan");
    expect(plan.repository.files).toBe(1);
    expect(plan.workspace.exists).toBe(false);
    expect(plan.missingInputs).toContain("vercel.authentication");
    expect(plan.actions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: "vercel-login", commands: ["npx vercel login"] }),
        expect.objectContaining({
          id: "vercel-link-workspace",
          commands: [expect.stringContaining(workspace), "npx vercel link"],
        }),
      ]),
    );
    expect(plan.documentation).toMatchObject({
      skill: path.join(workspace, "node_modules", "deepsec", "SKILL.md"),
      gettingStarted: path.join(
        workspace,
        "node_modules",
        "deepsec",
        "dist",
        "docs",
        "getting-started.md",
      ),
    });
    expect(fs.existsSync(workspace)).toBe(false);
  });
});

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { reconcileWorkspaceConfig } from "../setup/workspace-config.js";

describe("reconcileWorkspaceConfig", () => {
  it("persists the selected route, model combo, and default agent idempotently", () => {
    const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-config-"));
    const configPath = path.join(workspace, "deepsec.config.ts");
    fs.writeFileSync(configPath, "export default defineConfig({ projects: [] });\n");

    const route = {
      mode: "direct" as const,
      provider: "anthropic",
      apiKeyEnv: "MY_KEY",
    };
    reconcileWorkspaceConfig(workspace, route, "claude-agent-sdk", "claude-opus-5", "xhigh");
    reconcileWorkspaceConfig(workspace, route, "claude-agent-sdk", "claude-opus-5", "xhigh");

    const source = fs.readFileSync(configPath, "utf8");
    expect(source.match(/defaultAgent:/g)).toHaveLength(1);
    expect(source).toContain('defaultAgent: "claude-agent-sdk"');
    expect(source.match(/defaultModel:/g)).toHaveLength(1);
    expect(source).toContain('defaultModel: "claude-opus-5"');
    expect(source.match(/defaultThinkingLevel:/g)).toHaveLength(1);
    expect(source).toContain('defaultThinkingLevel: "xhigh"');
    expect(source.match(/<deepsec:model-route>/g)).toHaveLength(1);
    expect(source.match(/generatedMatchersPlugin/g)).toHaveLength(2);
  });
});

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import * as picker from "../auth/model-picker.js";
import * as routePrompt from "../auth/model-route-prompt.js";
import { initCommand } from "../commands/init.js";
import { modelRouteFromCli } from "../setup/options.js";
import { readWorkspaceConfigRoute } from "../setup/workspace-config.js";

describe("modelRouteFromCli", () => {
  it("defaults to the Vercel gateway", () => {
    expect(modelRouteFromCli({})).toEqual({ mode: "gateway", provider: "vercel" });
  });

  it.each(["local", "direct"] as const)("rejects an explicit %s route with fx", (mode) => {
    expect(() => modelRouteFromCli({ modelAuth: mode, aiProvider: "openai", agent: "fx" })).toThrow(
      `--agent fx can't use the ${mode} model route`,
    );
  });

  it("supports local subscriptions with no credential wiring", () => {
    expect(modelRouteFromCli({ modelAuth: "local" })).toEqual({ mode: "local", provider: "local" });
  });

  it("supports a direct user-owned key", () => {
    expect(
      modelRouteFromCli({
        modelAuth: "direct",
        agent: "codex",
        aiApiKeyEnv: "MY_OPENAI_KEY",
      }),
    ).toEqual({
      mode: "direct",
      provider: "openai",
      apiKeyEnv: "MY_OPENAI_KEY",
      baseUrl: undefined,
    });
  });

  it("requires complete custom credential routing", () => {
    expect(() => modelRouteFromCli({ modelAuth: "custom", aiProvider: "acme" })).toThrow(
      /requires --ai-api-key-env/,
    );
    expect(
      modelRouteFromCli({
        modelAuth: "custom",
        aiProvider: "acme",
        aiApiKeyEnv: "ACME_KEY",
        aiBaseUrl: "https://models.example.test/v1",
        aiCredentialHeader: "x-api-key:raw",
      }),
    ).toEqual({
      mode: "custom",
      provider: "acme",
      apiKeyEnv: "ACME_KEY",
      baseUrl: "https://models.example.test/v1",
      credentialHeader: { name: "x-api-key", scheme: "raw" },
    });
  });

  it("defaults authorization to bearer and other custom headers to raw", () => {
    const base = {
      modelAuth: "custom" as const,
      aiProvider: "acme",
      aiApiKeyEnv: "ACME_KEY",
      aiBaseUrl: "https://models.example.test/v1",
    };
    expect(
      modelRouteFromCli({ ...base, aiCredentialHeader: "authorization" }).credentialHeader,
    ).toEqual({ name: "authorization", scheme: "bearer" });
    expect(
      modelRouteFromCli({ ...base, aiCredentialHeader: "x-api-key" }).credentialHeader,
    ).toEqual({ name: "x-api-key", scheme: "raw" });
  });
});

describe("interactive setup route selection", () => {
  it("does not persist a local route when the final harness choice is fx", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-fx-init-"));
    const workspace = path.join(root, ".deepsec");
    const streams = [process.stdin, process.stdout];
    const descriptors = streams.map((s) => Object.getOwnPropertyDescriptor(s, "isTTY"));
    try {
      for (const stream of streams)
        Object.defineProperty(stream, "isTTY", { configurable: true, value: true });
      vi.spyOn(routePrompt, "promptForModelRoute").mockResolvedValue({
        route: { mode: "local", provider: "local" },
      });
      const select = vi
        .spyOn(picker, "promptForModelSelection")
        .mockResolvedValue({ agent: "fx", model: "test" });
      await expect(initCommand({ workspace, targetRoot: root, id: "app" })).rejects.toThrow(
        "--agent fx can't use the local model route",
      );
      expect(select).toHaveBeenCalledOnce();
      expect(readWorkspaceConfigRoute(workspace)?.mode).not.toBe("local");
    } finally {
      vi.restoreAllMocks();
      for (const [i, stream] of streams.entries()) {
        if (descriptors[i]) Object.defineProperty(stream, "isTTY", descriptors[i]!);
        else Reflect.deleteProperty(stream, "isTTY");
      }
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

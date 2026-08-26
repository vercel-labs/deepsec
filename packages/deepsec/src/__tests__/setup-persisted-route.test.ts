import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { persistedModelRoute, recordInitialModelRoute } from "../setup/persisted-route.js";
import {
  persistWorkspaceConfigRoute,
  readWorkspaceConfigRoute,
} from "../setup/workspace-config.js";

const LOCAL = { mode: "local" as const, provider: "local" };

function workspace(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-route-"));
  fs.writeFileSync(
    path.join(dir, "deepsec.config.ts"),
    "export default defineConfig({\n  projects: [],\n});\n",
  );
  return dir;
}

function writeConnectionCheckpoint(dir: string, projectId: string, route: unknown): void {
  const setupDir = path.join(dir, "data", projectId, "setup");
  fs.mkdirSync(setupDir, { recursive: true });
  fs.writeFileSync(
    path.join(setupDir, "setup-state.json"),
    JSON.stringify({
      version: 1,
      projectId,
      targetRoot: dir,
      phases: {},
      matcherAttempts: [],
      agent: { type: "claude-agent-sdk", model: "claude-opus-5" },
      connection: { route },
      updatedAt: "2026-01-01T00:00:00.000Z",
    }),
  );
}

describe("recordInitialModelRoute", () => {
  it("records a flag-supplied route, so an interrupt before install cannot lose it", () => {
    // `--model-auth local` is not repeated on resume, and setup writes its own
    // checkpoint only after login. Without this write, resuming an interrupted
    // run falls back to the gateway default.
    const dir = workspace();
    recordInitialModelRoute(dir, LOCAL);

    expect(persistedModelRoute(dir, "app")).toEqual(LOCAL);
  });

  it("leaves the recorded route alone for a resumed run, which carries none", () => {
    const dir = workspace();
    recordInitialModelRoute(dir, LOCAL);
    recordInitialModelRoute(dir, undefined);

    expect(readWorkspaceConfigRoute(dir)).toEqual(LOCAL);
  });
});

describe("persistedModelRoute", () => {
  it("reuses a local route persisted before the login checkpoint", () => {
    // Setup interrupted after the route prompt but before login: there is no
    // connection checkpoint, so init must not fall back to prompting for the
    // Vercel link or to the gateway route.
    const dir = workspace();
    persistWorkspaceConfigRoute(dir, LOCAL);

    expect(readWorkspaceConfigRoute(dir)).toEqual(LOCAL);
    expect(persistedModelRoute(dir, "app")).toEqual(LOCAL);
  });

  it("prefers the login checkpoint over the config route", () => {
    const dir = workspace();
    persistWorkspaceConfigRoute(dir, LOCAL);
    writeConnectionCheckpoint(dir, "app", { mode: "gateway", provider: "vercel" });

    expect(persistedModelRoute(dir, "app")).toEqual({ mode: "gateway", provider: "vercel" });
  });

  it("returns undefined when no route was recorded", () => {
    const dir = workspace();

    expect(readWorkspaceConfigRoute(dir)).toBeUndefined();
    expect(persistedModelRoute(dir, "app")).toBeUndefined();
    expect(persistedModelRoute(path.join(dir, "missing"), "app")).toBeUndefined();
  });

  it("ignores an unparseable route line", () => {
    const dir = workspace();
    persistWorkspaceConfigRoute(dir, LOCAL);
    const file = path.join(dir, "deepsec.config.ts");
    fs.writeFileSync(
      file,
      fs
        .readFileSync(file, "utf8")
        .replace(/ai: .*<deepsec:model-route>/, "ai: local, // <deepsec:model-route>"),
    );

    expect(readWorkspaceConfigRoute(dir)).toBeUndefined();
  });

  it("keeps a single route line when setup later reconciles the config", () => {
    const dir = workspace();
    persistWorkspaceConfigRoute(dir, LOCAL);
    persistWorkspaceConfigRoute(dir, LOCAL);

    const source = fs.readFileSync(path.join(dir, "deepsec.config.ts"), "utf8");
    expect(source.match(/<deepsec:model-route>/g)).toHaveLength(1);
  });
});

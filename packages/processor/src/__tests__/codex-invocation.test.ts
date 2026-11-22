import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildCodexInvocation, resolveCodexAuth } from "../agents/codex-sdk.js";

// Which credential the codex child process receives must follow the saved
// model route, not whichever API key happens to be exported in the shell.
const KEYS = [
  "OPENAI_API_KEY",
  "OPENAI_BASE_URL",
  "ANTHROPIC_AUTH_TOKEN",
  "ANTHROPIC_BASE_URL",
  "CODEX_HOME",
  "DEEPSEC_INSIDE_SANDBOX",
  "HOME",
  "USERPROFILE",
] as const;
const saved: Record<string, string | undefined> = {};
const tempDirs: string[] = [];
let fakeHome = "";

function tempCodexHome(withLogin: boolean): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "codex-route-test-"));
  tempDirs.push(dir);
  if (withLogin) fs.writeFileSync(path.join(dir, "auth.json"), "{}");
  return dir;
}

beforeEach(() => {
  for (const key of KEYS) {
    saved[key] = process.env[key];
    delete process.env[key];
  }
  // findCodexSubscriptionAuth falls back to os.homedir()/.codex. Point HOME
  // at an empty directory so the no-login case does not depend on the host.
  fakeHome = fs.mkdtempSync(path.join(os.tmpdir(), "codex-home-test-"));
  process.env.HOME = fakeHome;
  process.env.USERPROFILE = fakeHome;
});

afterEach(() => {
  for (const key of KEYS) {
    if (saved[key] === undefined) delete process.env[key];
    else process.env[key] = saved[key];
  }
  fs.rmSync(fakeHome, { recursive: true, force: true });
  for (const dir of tempDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe("buildCodexInvocation auth source", () => {
  it("uses the Codex login instead of an ambient OPENAI_API_KEY for a local route", () => {
    process.env.OPENAI_API_KEY = "sk-ambient-unrelated";
    process.env.CODEX_HOME = tempCodexHome(true);

    const invocation = buildCodexInvocation({ modelAuth: "local" });
    tempDirs.push(invocation.codexHome);

    expect(invocation.options.apiKey).toBeUndefined();
    expect(invocation.options.env?.OPENAI_API_KEY).toBeUndefined();
    expect(fs.existsSync(path.join(invocation.codexHome, "auth.json"))).toBe(true);
  });

  it("falls back to gateway auth when a local route has no Codex login but an ambient key", () => {
    // `ai.mode: "local"` is harness-agnostic: it records a machine-wide login,
    // not proof that the login is Codex. A user who picked it for Claude and
    // runs --agent codex with a legitimate OPENAI_API_KEY must get a working
    // gateway run, not a mid-batch throw.
    process.env.OPENAI_API_KEY = "sk-ambient-unrelated";
    process.env.CODEX_HOME = tempCodexHome(false);

    const invocation = buildCodexInvocation({ modelAuth: "local" });
    tempDirs.push(invocation.codexHome);

    expect(invocation.options.apiKey).toBe("sk-ambient-unrelated");
    expect(invocation.options.env?.OPENAI_API_KEY).toBe("sk-ambient-unrelated");
    expect(fs.existsSync(path.join(invocation.codexHome, "auth.json"))).toBe(false);
  });

  it("falls back to an ambient ANTHROPIC_AUTH_TOKEN when a local route has no Codex login", () => {
    process.env.ANTHROPIC_AUTH_TOKEN = "sk-ant-ambient";
    process.env.ANTHROPIC_BASE_URL = "https://ai-gateway.vercel.sh";
    process.env.CODEX_HOME = tempCodexHome(false);

    const invocation = buildCodexInvocation({ modelAuth: "local" });
    tempDirs.push(invocation.codexHome);

    expect(invocation.options.apiKey).toBe("sk-ant-ambient");
    expect(invocation.options.env?.OPENAI_API_KEY).toBe("sk-ant-ambient");
  });

  it("does not throw mid-run when a local route has no Codex login and no ambient key", () => {
    // Preflight rejects this combination before scanning starts
    // (packages/deepsec/src/preflight.ts); the backend must not throw per batch.
    process.env.CODEX_HOME = tempCodexHome(false);

    const invocation = buildCodexInvocation({ modelAuth: "local" });
    tempDirs.push(invocation.codexHome);

    expect(invocation.options.apiKey).toBeUndefined();
    expect(invocation.options.env?.OPENAI_API_KEY).toBeUndefined();
  });

  it("still forwards the route credential when the route is not local", () => {
    process.env.OPENAI_API_KEY = "sk-route-key";

    const invocation = buildCodexInvocation({ modelAuth: "gateway" });
    tempDirs.push(invocation.codexHome);

    expect(invocation.options.apiKey).toBe("sk-route-key");
    expect(invocation.options.env?.OPENAI_API_KEY).toBe("sk-route-key");
  });

  it("keeps gateway auth for a local route inside a sandbox worker", () => {
    process.env.DEEPSEC_INSIDE_SANDBOX = "1";
    process.env.OPENAI_API_KEY = "vck-brokered";
    process.env.CODEX_HOME = tempCodexHome(true);

    const invocation = buildCodexInvocation({ modelAuth: "local" });
    tempDirs.push(invocation.codexHome);

    expect(invocation.options.apiKey).toBe("vck-brokered");
  });
});

describe("resolveCodexAuth", () => {
  it("treats a saved local route as subscription auth when a Codex login exists", () => {
    process.env.OPENAI_API_KEY = "sk-ambient-unrelated";
    process.env.CODEX_HOME = tempCodexHome(true);

    expect(resolveCodexAuth({ modelAuth: "local" })).toMatchObject({
      mode: "subscription",
      localRoute: true,
      gatewayApiKey: "sk-ambient-unrelated",
    });
  });

  it("falls back to gateway auth when the saved local route has no Codex login", () => {
    process.env.OPENAI_API_KEY = "sk-ambient-unrelated";
    process.env.CODEX_HOME = tempCodexHome(false);

    expect(resolveCodexAuth({ modelAuth: "local" })).toMatchObject({
      mode: "gateway",
      localRoute: true,
      subscriptionHome: null,
      gatewayApiKey: "sk-ambient-unrelated",
    });
  });

  it("keeps the pre-existing gateway preference when no local route is saved", () => {
    process.env.OPENAI_API_KEY = "sk-route-key";
    process.env.CODEX_HOME = tempCodexHome(true);

    expect(resolveCodexAuth({})).toMatchObject({ mode: "gateway", localRoute: false });
  });

  it("keeps the pre-existing subscription default when no route or key is set", () => {
    process.env.CODEX_HOME = tempCodexHome(true);

    expect(resolveCodexAuth({})).toMatchObject({
      mode: "subscription",
      localRoute: false,
      gatewayApiKey: undefined,
    });
  });

  it("always uses gateway auth inside a sandbox worker", () => {
    process.env.DEEPSEC_INSIDE_SANDBOX = "1";
    process.env.CODEX_HOME = tempCodexHome(true);

    expect(resolveCodexAuth({ modelAuth: "local" })).toMatchObject({
      mode: "gateway",
      localRoute: false,
    });
  });
});

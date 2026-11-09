import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildCodexInvocation } from "../agents/codex-sdk.js";

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

  it("reports a missing Codex login instead of falling back to an ambient key", () => {
    process.env.OPENAI_API_KEY = "sk-ambient-unrelated";
    process.env.CODEX_HOME = tempCodexHome(false);

    expect(() => buildCodexInvocation({ modelAuth: "local" })).toThrow(/local-subscription/i);
  });

  it("still forwards the route credential when the route is not local", () => {
    process.env.OPENAI_API_KEY = "sk-route-key";

    const invocation = buildCodexInvocation({ modelAuth: "gateway" });
    tempDirs.push(invocation.codexHome);

    expect(invocation.options.apiKey).toBe("sk-route-key");
    expect(invocation.options.env?.OPENAI_API_KEY).toBe("sk-route-key");
  });
});

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  buildCodexInvocation,
  findCodexSubscriptionHome,
  resolveCodexAuth,
  resolveCodexLoginHome,
} from "../agents/codex-sdk.js";

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

function tempDir(prefix = "codex-route-test-"): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

/** A directory in the shape of `$CODEX_HOME` (or `~/.codex`), optionally logged in. */
function tempCodexHome(withLogin: boolean): string {
  const dir = tempDir();
  if (withLogin) fs.writeFileSync(path.join(dir, "auth.json"), "{}");
  return dir;
}

/** A user home directory containing `.codex/auth.json`, optionally logged in. */
function tempUserHome(withLogin: boolean): string {
  const home = tempDir("codex-user-home-test-");
  fs.mkdirSync(path.join(home, ".codex"), { recursive: true });
  if (withLogin) fs.writeFileSync(path.join(home, ".codex", "auth.json"), "{}");
  return home;
}

beforeEach(() => {
  for (const key of KEYS) {
    saved[key] = process.env[key];
    delete process.env[key];
  }
  // The resolver falls back to $HOME/.codex. Point HOME at an empty
  // directory so the no-login case does not depend on the host.
  fakeHome = tempDir("codex-home-test-");
  process.env.HOME = fakeHome;
  process.env.USERPROFILE = fakeHome;
});

afterEach(() => {
  for (const key of KEYS) {
    if (saved[key] === undefined) delete process.env[key];
    else process.env[key] = saved[key];
  }
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

  // Fail closed: a saved local route is an explicit subscription-auth choice.
  // When the Codex login is gone, an unrelated ambient key must not silently
  // reroute the run through gateway auth.
  it("fails closed instead of using an ambient OPENAI_API_KEY for a local route with no login", () => {
    process.env.OPENAI_API_KEY = "sk-ambient-unrelated";
    process.env.CODEX_HOME = tempCodexHome(false);

    expect(() => buildCodexInvocation({ modelAuth: "local" })).toThrow(/codex login/);
    expect(() => buildCodexInvocation({ modelAuth: "local" })).toThrow(/--model-auth gateway/);
  });

  it("fails closed instead of using an ambient ANTHROPIC_AUTH_TOKEN for a local route with no login", () => {
    process.env.ANTHROPIC_AUTH_TOKEN = "sk-ant-ambient";
    process.env.ANTHROPIC_BASE_URL = "https://ai-gateway.vercel.sh";
    process.env.CODEX_HOME = tempCodexHome(false);

    expect(() => buildCodexInvocation({ modelAuth: "local" })).toThrow(/no Codex login/);
  });

  it("fails closed when a local route has neither a login nor an ambient key", () => {
    process.env.CODEX_HOME = tempCodexHome(false);

    expect(() => buildCodexInvocation({ modelAuth: "local" })).toThrow(/codex login/);
  });

  it("still forwards the route credential when the route is not local", () => {
    process.env.OPENAI_API_KEY = "sk-route-key";

    const invocation = buildCodexInvocation({ modelAuth: "gateway" });
    tempDirs.push(invocation.codexHome);

    expect(invocation.options.apiKey).toBe("sk-route-key");
    expect(invocation.options.env?.OPENAI_API_KEY).toBe("sk-route-key");
  });

  it("keeps discovering the ambient gateway credential when no route is saved", () => {
    process.env.OPENAI_API_KEY = "sk-ambient";

    const invocation = buildCodexInvocation({});
    tempDirs.push(invocation.codexHome);

    expect(invocation.options.apiKey).toBe("sk-ambient");
    expect(invocation.options.env?.OPENAI_API_KEY).toBe("sk-ambient");
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
      hasGatewayApiKey: true,
    });
  });

  it("reports a missing login for a saved local route instead of switching to gateway", () => {
    process.env.OPENAI_API_KEY = "sk-ambient-unrelated";
    process.env.CODEX_HOME = tempCodexHome(false);

    expect(resolveCodexAuth({ modelAuth: "local" })).toMatchObject({
      mode: "unavailable",
      localRoute: true,
      subscriptionHome: null,
      hasGatewayApiKey: true,
    });
  });

  it("keeps the pre-existing gateway preference when no local route is saved", () => {
    process.env.OPENAI_API_KEY = "sk-route-key";
    process.env.CODEX_HOME = tempCodexHome(true);

    expect(resolveCodexAuth({})).toMatchObject({
      mode: "gateway",
      localRoute: false,
      hasGatewayApiKey: true,
    });
  });

  it("keeps the pre-existing subscription default when no route or key is set", () => {
    process.env.CODEX_HOME = tempCodexHome(true);

    expect(resolveCodexAuth({})).toMatchObject({
      mode: "subscription",
      localRoute: false,
      hasGatewayApiKey: false,
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

  it("never exposes the raw gateway credential", () => {
    process.env.OPENAI_API_KEY = "sk-secret-value";
    process.env.CODEX_HOME = tempCodexHome(false);

    const decision = resolveCodexAuth({});
    expect(decision).not.toHaveProperty("gatewayApiKey");
    expect(JSON.stringify(decision)).not.toContain("sk-secret-value");
  });
});

describe("findCodexSubscriptionHome (back-compat)", () => {
  it("keeps the pre-PR no-arg behavior", () => {
    process.env.CODEX_HOME = tempCodexHome(true);
    expect(findCodexSubscriptionHome()).toBe(process.env.CODEX_HOME);

    process.env.OPENAI_API_KEY = "sk-ambient";
    expect(findCodexSubscriptionHome()).toBeNull();
  });
});

describe("resolveCodexLoginHome", () => {
  it("prefers CODEX_HOME over the user home", () => {
    const codexHome = tempCodexHome(true);
    process.env.CODEX_HOME = codexHome;
    process.env.HOME = tempUserHome(true);

    expect(resolveCodexLoginHome()).toBe(codexHome);
  });

  it("resolves $HOME/.codex when CODEX_HOME is unset", () => {
    const home = tempUserHome(true);
    process.env.HOME = home;

    expect(resolveCodexLoginHome()).toBe(path.join(home, ".codex"));
  });

  // HOME can diverge from the OS home (sudo -E, systemd/launchd units, CI
  // jobs that override HOME). The backend honors USERPROFILE when HOME is
  // missing, and preflight must make the same decision.
  it("resolves USERPROFILE/.codex when HOME is unset", () => {
    const userHome = tempUserHome(true);
    delete process.env.HOME;
    process.env.USERPROFILE = userHome;

    expect(resolveCodexLoginHome()).toBe(path.join(userHome, ".codex"));
  });

  it("returns null when no candidate holds auth.json", () => {
    process.env.HOME = tempUserHome(false);

    expect(resolveCodexLoginHome()).toBeNull();
  });
});

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buildCodexInvocation } from "../agents/codex-sdk.js";

describe("buildCodexInvocation cyberAccessProgram", () => {
  const created: string[] = [];

  beforeEach(() => {
    const userHome = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-codex-user-"));
    fs.writeFileSync(path.join(userHome, "auth.json"), "{}");
    created.push(userHome);
    vi.stubEnv("CODEX_HOME", userHome);
    vi.stubEnv("OPENAI_API_KEY", "");
    vi.stubEnv("ANTHROPIC_AUTH_TOKEN", "");
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    for (const dir of created.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
  });

  function invoke() {
    const invocation = buildCodexInvocation("daybreak_blue");
    created.push(invocation.codexHome);
    return invocation;
  }

  it("keeps the program on a subscription login", () => {
    expect(invoke().cyberAccessProgram).toBe("daybreak_blue");
  });

  it("drops the program when an API token routes codex through the gateway", () => {
    vi.stubEnv("OPENAI_API_KEY", "sk-test");
    expect(invoke().cyberAccessProgram).toBeUndefined();
  });
});

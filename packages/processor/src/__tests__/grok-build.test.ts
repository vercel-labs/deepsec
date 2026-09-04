import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildGrokEnv, makeIsolatedGrokHome, parseGrokStdout } from "../agents/grok-build.js";
import { createDefaultAgentRegistry } from "../index.js";

const homes: string[] = [];

afterEach(() => {
  for (const home of homes.splice(0)) {
    try {
      fs.rmSync(home, { recursive: true, force: true });
    } catch {
      // ignore
    }
  }
});

describe("Grok Build agent", () => {
  it("registers as type 'grok' in the default agent registry", () => {
    const registry = createDefaultAgentRegistry();
    expect(registry.types()).toContain("grok");
    expect(registry.get("grok")?.type).toBe("grok");
  });

  it("buildGrokEnv allowlists only safe vars and injects GROK_HOME", () => {
    const prev = { ...process.env };
    try {
      process.env.PATH = "/usr/bin";
      process.env.HOME = "/Users/test";
      process.env.XAI_API_KEY = "xai-test-key";
      process.env.GITHUB_TOKEN = "should-not-leak";
      process.env.AWS_SECRET_ACCESS_KEY = "should-not-leak";
      process.env.LC_ALL = "en_US.UTF-8";

      const env = buildGrokEnv("/tmp/fake-grok-home");
      expect(env.GROK_HOME).toBe("/tmp/fake-grok-home");
      expect(env.GROK_DISABLE_AUTOUPDATER).toBe("1");
      expect(env.XAI_API_KEY).toBe("xai-test-key");
      expect(env.PATH).toBe("/usr/bin");
      expect(env.LC_ALL).toBe("en_US.UTF-8");
      expect(env.GITHUB_TOKEN).toBeUndefined();
      expect(env.AWS_SECRET_ACCESS_KEY).toBeUndefined();
    } finally {
      process.env = prev;
    }
  });

  it("parseGrokStdout recovers a banner + nested JSON object", () => {
    const raw = parseGrokStdout(
      'note: starting\n{"text":"{\\"ok\\":true}","usage":{"input_tokens":12},"sessionId":"abc","num_turns":1}\n',
    );
    expect(raw.text).toBe('{"ok":true}');
    expect(raw.sessionId).toBe("abc");
    expect(raw.usage?.input_tokens).toBe(12);
  });

  it("makeIsolatedGrokHome creates a config and mirrors auth when available", () => {
    const seed = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-grok-seed-"));
    homes.push(seed);
    fs.writeFileSync(path.join(seed, "auth.json"), JSON.stringify({ token: "test" }), {
      mode: 0o600,
    });
    const prev = process.env.GROK_HOME;
    process.env.GROK_HOME = seed;
    try {
      const home = makeIsolatedGrokHome();
      homes.push(home);
      expect(fs.existsSync(path.join(home, "config.toml"))).toBe(true);
      expect(fs.existsSync(path.join(home, "auth.json"))).toBe(true);
      expect(fs.existsSync(path.join(home, "skills"))).toBe(false);
    } finally {
      if (prev === undefined) delete process.env.GROK_HOME;
      else process.env.GROK_HOME = prev;
    }
  });
});

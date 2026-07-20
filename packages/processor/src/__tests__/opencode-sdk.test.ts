import { afterEach, describe, expect, it } from "vitest";
import {
  buildOpenCodeConfig,
  formatOpenCodeError,
  parseOpenCodeModel,
  resolveOpenCodeAssistantText,
  resolveOpenCodeVariant,
  shouldUseOpenCodeTextFormat,
} from "../agents/opencode-sdk.js";

describe("OpenCodeAgentPlugin configuration", () => {
  const savedEnv = {
    ANTHROPIC_AUTH_TOKEN: process.env.ANTHROPIC_AUTH_TOKEN,
    ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY,
    ANTHROPIC_BASE_URL: process.env.ANTHROPIC_BASE_URL,
    OPENAI_API_KEY: process.env.OPENAI_API_KEY,
    OPENAI_BASE_URL: process.env.OPENAI_BASE_URL,
  };

  afterEach(() => {
    for (const [key, value] of Object.entries(savedEnv)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });

  it("parses provider/model while preserving slashes in the model id", () => {
    expect(parseOpenCodeModel("openai/acme/gpt-sec")).toEqual({
      providerID: "openai",
      modelID: "acme/gpt-sec",
    });
  });

  it("rejects a bare model name with an actionable example", () => {
    expect(() => parseOpenCodeModel("claude-opus")).toThrow(/provider\/model/);
    expect(() => parseOpenCodeModel("claude-opus")).toThrow(/anthropic\/claude-opus-4-8/);
  });

  it("maps the shared thinking dial to provider variants", () => {
    expect(resolveOpenCodeVariant("anthropic", "xhigh")).toBe("max");
    expect(resolveOpenCodeVariant("anthropic", "medium")).toBe("high");
    expect(resolveOpenCodeVariant("openai", "low")).toBe("low");
    expect(resolveOpenCodeVariant("google", "minimal")).toBe("low");
    expect(resolveOpenCodeVariant("google", "high")).toBe("high");
    expect(resolveOpenCodeVariant("custom")).toBeUndefined();
    expect(resolveOpenCodeVariant("custom", "medium")).toBe("medium");
  });

  it("uses text output when Anthropic thinking conflicts with forced structured output", () => {
    expect(
      shouldUseOpenCodeTextFormat("anthropic", "high", {
        type: "json_schema",
        schema: { type: "object" },
      }),
    ).toBe(true);
    expect(
      shouldUseOpenCodeTextFormat("anthropic", undefined, {
        type: "json_schema",
        schema: { type: "object" },
      }),
    ).toBe(false);
    expect(
      shouldUseOpenCodeTextFormat("openai", "high", {
        type: "json_schema",
        schema: { type: "object" },
      }),
    ).toBe(false);
    expect(shouldUseOpenCodeTextFormat("anthropic", "high", { type: "text" })).toBe(false);
  });

  it("preserves nested network error details", () => {
    const cause = Object.assign(new Error("Headers Timeout Error"), {
      code: "UND_ERR_HEADERS_TIMEOUT",
    });
    const error = new TypeError("fetch failed", { cause });

    expect(formatOpenCodeError(error)).toBe(
      "fetch failed: Headers Timeout Error (UND_ERR_HEADERS_TIMEOUT)",
    );
  });

  it("uses plain text when a provider skips OpenCode's StructuredOutput tool", () => {
    expect(
      resolveOpenCodeAssistantText(
        {
          error: {
            name: "StructuredOutputError",
            data: {
              message: "Model did not produce structured output",
              retries: 0,
            },
          },
        },
        '[{"filePath":"src/a.ts","findings":[]}]',
      ),
    ).toEqual({
      resultText: '[{"filePath":"src/a.ts","findings":[]}]',
      recoveredStructuredText: true,
    });
  });

  it("keeps a structured-output failure when the provider returned no text", () => {
    expect(() =>
      resolveOpenCodeAssistantText(
        {
          error: {
            name: "StructuredOutputError",
            data: {
              message: "Model did not produce structured output",
              retries: 0,
            },
          },
        },
        "",
      ),
    ).toThrow(/StructuredOutputError: Model did not produce structured output/);
  });

  it("enforces read-only tools, capped steps, and structured provider routing", () => {
    process.env.ANTHROPIC_AUTH_TOKEN = "do-not-inline-this-secret";
    process.env.ANTHROPIC_BASE_URL = "https://ai-gateway.example";

    const config = buildOpenCodeConfig({
      model: "anthropic/claude-opus-4-8",
      maxTurns: 42,
      thinkingLevel: "xhigh",
    });
    const main = config.agent?.deepsec;

    expect(config.default_agent).toBe("deepsec");
    expect(config.share).toBe("disabled");
    expect(config.autoupdate).toBe(false);
    expect(config.tools).toMatchObject({
      read: true,
      glob: true,
      grep: true,
      list: true,
      bash: false,
      edit: false,
      task: false,
      webfetch: false,
    });
    expect(config.permission).toMatchObject({
      "*": "deny",
      read: "allow",
      bash: "deny",
      edit: "deny",
      external_directory: "deny",
    });
    expect(main?.steps).toBe(42);
    expect(main?.variant).toBe("max");
    expect(main?.permission).toEqual(config.permission);
    expect(config.provider?.anthropic?.options).toMatchObject({
      apiKey: "{env:ANTHROPIC_AUTH_TOKEN}",
      baseURL: "https://ai-gateway.example/v1",
    });
    expect(JSON.stringify(config)).not.toContain("do-not-inline-this-secret");
  });

  it("does not duplicate the Anthropic API version path", () => {
    process.env.ANTHROPIC_BASE_URL = "https://api.anthropic.com/v1/";

    const config = buildOpenCodeConfig({
      model: "anthropic/claude-haiku-4-5",
    });

    expect(config.provider?.anthropic?.options?.baseURL).toBe("https://api.anthropic.com/v1");
  });

  it("supports a custom provider override without changing the model id", () => {
    process.env.MARTIAN_API_KEY = "secret";
    const config = buildOpenCodeConfig({
      model: "openai/org/model",
      aiProvider: "martian",
      aiBaseUrl: "https://martian.example/v1",
      aiApiKeyEnv: "MARTIAN_API_KEY",
      aiHeaders: { "x-team": "security" },
    });

    expect(config.model).toBe("martian/org/model");
    expect(config.provider?.martian).toEqual({
      options: {
        apiKey: "{env:MARTIAN_API_KEY}",
        baseURL: "https://martian.example/v1",
      },
      headers: { "x-team": "security" },
    });
  });
});

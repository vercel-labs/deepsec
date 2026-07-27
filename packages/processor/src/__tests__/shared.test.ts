import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  buildInvestigateFieldRepairPrompt,
  buildInvestigateJsonRepairPrompt,
  buildRevalidateJsonRepairPrompt,
  classifyQuotaError,
  formatMissingCodexBinaryError,
  formatJsonRepairFailureDebugText,
  isMissingBinaryError,
  isTransientError,
  isUsingAiGateway,
  parseInvestigateResults,
  parseRefusalReport,
  parseRevalidateVerdicts,
  QuotaExhaustedError,
  runInvestigateFieldRepairLoop,
  writeParseFailureDebug,
} from "../agents/shared.js";

describe("isTransientError", () => {
  it("flags 5xx, 429, eager_input_streaming, ECONNRESET", () => {
    expect(isTransientError("HTTP 503 Service Unavailable")).toBe(true);
    expect(isTransientError("HTTP 429 too many requests")).toBe(true);
    expect(isTransientError("Extra inputs are not permitted: eager_input_streaming")).toBe(true);
    expect(isTransientError("ECONNRESET fetch failed")).toBe(true);
    expect(isTransientError("rate-limit hit")).toBe(true);
    expect(isTransientError("overloaded")).toBe(true);
  });

  it("doesn't flag obvious permanent errors", () => {
    expect(isTransientError("ENOENT no such file")).toBe(false);
    expect(
      isTransientError(
        "spawn /Users/me/project/node_modules/@openai/codex/vendor/aarch64-apple-darwin/codex/codex ENOENT",
      ),
    ).toBe(false);
    expect(isTransientError("invalid api key")).toBe(false);
  });

  it("does NOT classify quota errors as transient (defense-in-depth)", () => {
    // A 429 carrying an `insufficient_quota` body would otherwise loop in
    // the retry budget; classifyQuotaError takes precedence so we don't
    // burn attempts on a permanently-empty wallet.
    expect(isTransientError("HTTP 429 insufficient_quota: You exceeded your current quota")).toBe(
      false,
    );
    expect(isTransientError("Claude AI usage limit reached for the week")).toBe(false);
  });
});

describe("isMissingBinaryError", () => {
  const vendorPath =
    "/Users/me/project/node_modules/@openai/codex/vendor/aarch64-apple-darwin/codex/codex";

  it("matches vendored Codex spawn ENOENT failures", () => {
    expect(isMissingBinaryError(`spawn ${vendorPath} ENOENT`)).toBe(true);
    expect(
      isMissingBinaryError(
        `Codex Exec exited with signal SIGKILL\nError: spawn ${vendorPath} ENOENT`,
      ),
    ).toBe(true);
  });

  it("does not match SIGKILL-only text or unrelated ENOENT failures", () => {
    expect(isMissingBinaryError("Codex Exec exited with signal SIGKILL")).toBe(false);
    expect(isMissingBinaryError("spawn /tmp/codex ENOENT")).toBe(false);
    expect(isMissingBinaryError("ENOENT no such file")).toBe(false);
  });

  it("does not match transient or quota failures", () => {
    expect(isMissingBinaryError("HTTP 429 too many requests")).toBe(false);
    expect(isMissingBinaryError("ETIMEDOUT")).toBe(false);
    expect(isMissingBinaryError("timeout waiting for Codex")).toBe(false);
    expect(isMissingBinaryError("You've hit your usage limit.")).toBe(false);
    expect(isMissingBinaryError("HTTP 429 insufficient_quota")).toBe(false);
  });
});

describe("formatMissingCodexBinaryError", () => {
  it("includes the failing path and macOS quarantine remediation", () => {
    const vendorPath =
      "/Users/me/project/node_modules/@openai/codex/vendor/aarch64-apple-darwin/codex/codex";
    const formatted = formatMissingCodexBinaryError(`spawn ${vendorPath} ENOENT`);

    expect(formatted).toContain(vendorPath);
    expect(formatted).toContain("Gatekeeper");
    expect(formatted).toContain("quarantine");
    expect(formatted).toContain("reinstall dependencies");
    expect(formatted).toContain("xattr -dr com.apple.quarantine");
    expect(formatted).not.toContain("produced no result");
  });
});

describe("classifyQuotaError", () => {
  // Strings in this block were extracted from the actual platform binaries
  // shipped via @anthropic-ai/claude-agent-sdk-darwin-arm64 (claude) and
  // @openai/codex/vendor/.../bin/codex (codex Rust binary), via
  // `strings | grep`. Treat these tests as ground truth — if a binary
  // upgrade breaks them, the regexes need updating.

  it("Claude binary: 'Credit balance is too low' (with 'is')", () => {
    expect(classifyQuotaError("Credit balance is too low", "claude")).toBe("anthropic-credits");
    expect(
      classifyQuotaError("Your credit balance is too low to access the Claude API", "claude"),
    ).toBe("anthropic-credits");
  });

  it("Claude binary: 'Credit balance too low' (without 'is') + funds URL", () => {
    expect(
      classifyQuotaError(
        "Credit balance too low · Add funds: https://platform.claude.com/settings/billing",
        "claude",
      ),
    ).toBe("anthropic-credits");
  });

  it("Anthropic structured tags: billing_error / out_of_credits / credit_balance_low", () => {
    expect(classifyQuotaError('{"type":"billing_error","message":"…"}', "claude")).toBe(
      "anthropic-credits",
    );
    expect(classifyQuotaError("event=out_of_credits", "claude")).toBe("anthropic-credits");
    expect(classifyQuotaError("error_code: credit_balance_low", "claude")).toBe(
      "anthropic-credits",
    );
  });

  it("Claude subscription prose ('usage limit', 'weekly limit') — needs hint to disambiguate", () => {
    // Same prose appears in both binaries; the agent hint resolves source.
    expect(classifyQuotaError("usage limit reached", "claude")).toBe("claude-subscription");
    expect(classifyQuotaError("Hit the weekly limit", "claude")).toBe("claude-subscription");
    expect(classifyQuotaError("/upgrade to increase your usage limit.", "claude")).toBe(
      "claude-subscription",
    );
    // Without a hint, it's still classified — falls back to 'unknown' so
    // the run still bails (the alternative is to silently retry, which
    // wastes the budget).
    expect(classifyQuotaError("usage limit reached")).toBe("unknown");
  });

  it("Codex binary: canonical 'You've hit your usage limit' phrasing", () => {
    expect(classifyQuotaError("You've hit your usage limit.", "codex")).toBe("openai-subscription");
    expect(
      classifyQuotaError(
        "You've hit your usage limit. Upgrade to Plus to continue using Codex (https://chatgpt.com/explore/plus)",
        "codex",
      ),
    ).toBe("openai-subscription");
    expect(
      classifyQuotaError(
        "You've hit your usage limit. Visit https://chatgpt.com/codex/settings/usage to purchase more credits",
        "codex",
      ),
    ).toBe("openai-subscription");
    expect(
      classifyQuotaError(
        "You've hit your usage limit. To get more access now, send a request to your admin",
        "codex",
      ),
    ).toBe("openai-subscription");
  });

  it("Codex internal tags: workspace_*_credits_depleted / *_usage_limit_reached / usageLimitExceeded", () => {
    expect(classifyQuotaError("workspace_owner_credits_depleted", "codex")).toBe(
      "openai-subscription",
    );
    expect(classifyQuotaError("workspace_member_credits_depleted", "codex")).toBe(
      "openai-subscription",
    );
    expect(classifyQuotaError("workspace_owner_usage_limit_reached", "codex")).toBe(
      "openai-subscription",
    );
    expect(classifyQuotaError("usage_limit_exceeded", "codex")).toBe("openai-subscription");
    expect(classifyQuotaError("usageLimitExceeded", "codex")).toBe("openai-subscription");
  });

  it("Direct OpenAI API: insufficient_quota / 'You exceeded your current quota'", () => {
    expect(classifyQuotaError("HTTP 429 insufficient_quota", "codex")).toBe("openai-quota");
    expect(
      classifyQuotaError(
        "You exceeded your current quota, please check your plan and billing",
        "codex",
      ),
    ).toBe("openai-quota");
  });

  it("Vercel AI Gateway: literal strings extracted from gateway source code", () => {
    // Strings extracted from vercel/ai-gateway. These are the exact
    // bodies the gateway emits to clients (see check-billing.ts:33-47,
    // check-quota-entity.ts:77-85, check-video-eligibility.ts:151-308).
    // The gateway WRAPS upstream provider errors rather than passing them
    // through, so client-facing bodies always carry these canonical types.

    // HTTP 402 — insufficient_funds (the headline scenario).
    expect(
      classifyQuotaError(
        '{"error":{"message":"Insufficient funds. Please add credits to your account to continue using AI services. Visit https://vercel.com/d?to=%2F%5Bteam%5D%2F%7E%2Fai%3Fmodal%3Dtop-up to top up your credits.","type":"insufficient_funds"}}',
      ),
    ).toBe("gateway-credits");
    expect(classifyQuotaError("error.type=insufficient_funds")).toBe("gateway-credits");

    // HTTP 403 — customer_verification_required (no card on file).
    expect(
      classifyQuotaError("AI Gateway requires a valid credit card on file to service requests."),
    ).toBe("gateway-credits");
    expect(classifyQuotaError("type: customer_verification_required")).toBe("gateway-credits");

    // HTTP 429 — admin-set quota for an entity.
    expect(
      classifyQuotaError(
        'Quota limit exceeded for "team-x". Current spend: $50.00, limit: $50.00. Please contact your administrator to increase the quota.',
      ),
    ).toBe("gateway-credits");
    expect(classifyQuotaError("type: quota_for_entity_exceeded")).toBe("gateway-credits");
  });

  it("Vercel AI Gateway prose wins over provider attribution in the same body", () => {
    // The gateway WRAPS provider errors, but if any historical/loose
    // pattern leaks through with provider names alongside gateway
    // attribution, we want gateway-credits to win.
    expect(classifyQuotaError("AI Gateway: insufficient credits")).toBe("gateway-credits");
    expect(classifyQuotaError("ai_gateway: payment required")).toBe("gateway-credits");
    expect(classifyQuotaError("insufficient credits")).toBe("gateway-credits");
  });

  it("returns undefined for non-quota errors so retry/transient logic still applies", () => {
    expect(classifyQuotaError("HTTP 503 Service Unavailable")).toBeUndefined();
    expect(classifyQuotaError("ECONNRESET")).toBeUndefined();
    expect(classifyQuotaError("ENOENT")).toBeUndefined();
    expect(classifyQuotaError("")).toBeUndefined();
  });

  it("falls back to 'unknown' for bare HTTP 402 with payment-required", () => {
    expect(classifyQuotaError("HTTP 402 Payment Required (insufficient)")).toBe("unknown");
  });
});

describe("QuotaExhaustedError", () => {
  it("carries source + raw, and the message includes both", () => {
    const e = new QuotaExhaustedError("anthropic-credits", "Your credit balance is too low");
    expect(e.source).toBe("anthropic-credits");
    expect(e.rawMessage).toContain("credit balance");
    expect(e.message).toContain("anthropic-credits");
    expect(e.name).toBe("QuotaExhaustedError");
    expect(e instanceof Error).toBe(true);
  });
});

describe("isUsingAiGateway", () => {
  // We mutate process.env directly — capture and restore so tests don't
  // bleed environment into each other.
  const KEYS = ["AI_GATEWAY_API_KEY", "ANTHROPIC_BASE_URL", "OPENAI_BASE_URL"] as const;
  const saved: Record<string, string | undefined> = {};
  beforeEach(() => {
    for (const k of KEYS) saved[k] = process.env[k];
    for (const k of KEYS) delete process.env[k];
  });
  afterEach(() => {
    for (const k of KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  it("returns true when AI_GATEWAY_API_KEY is set", () => {
    process.env.AI_GATEWAY_API_KEY = "vck_x";
    expect(isUsingAiGateway()).toBe(true);
  });

  it("returns true when ANTHROPIC_BASE_URL points at the gateway", () => {
    process.env.ANTHROPIC_BASE_URL = "https://ai-gateway.vercel.sh";
    expect(isUsingAiGateway()).toBe(true);
  });

  it("returns true when OPENAI_BASE_URL points at the gateway (with trailing slash)", () => {
    process.env.OPENAI_BASE_URL = "https://ai-gateway.vercel.sh/v1/";
    expect(isUsingAiGateway()).toBe(true);
  });

  it("returns false when neither base URL points at the gateway", () => {
    process.env.ANTHROPIC_BASE_URL = "https://api.anthropic.com";
    process.env.OPENAI_BASE_URL = "https://api.openai.com/v1";
    expect(isUsingAiGateway()).toBe(false);
  });

  it("returns false when no relevant env vars are set", () => {
    expect(isUsingAiGateway()).toBe(false);
  });
});

describe("parseRefusalReport", () => {
  it("parses fenced JSON with refused: true", () => {
    const raw =
      '```json\n{"refused": true, "reason": "policy", "skipped": [{"filePath":"a.ts","reason":"x"}]}\n```';
    const r = parseRefusalReport(raw);
    expect(r?.refused).toBe(true);
    expect(r?.reason).toBe("policy");
    expect(r?.skipped).toEqual([{ filePath: "a.ts", reason: "x" }]);
  });

  it("parses bare JSON with refused: false", () => {
    const r = parseRefusalReport('{"refused": false, "skipped": []}');
    expect(r?.refused).toBe(false);
    expect(r?.skipped).toEqual([]);
  });

  it("falls back to heuristic on non-JSON refusal text", () => {
    const r = parseRefusalReport("I can't analyze this content.");
    expect(r?.refused).toBe(true);
    expect(r?.reason).toContain("heuristic");
  });

  it("returns undefined on empty input", () => {
    expect(parseRefusalReport("")).toBeUndefined();
  });
});

describe("JSON repair prompts", () => {
  it("asks investigation agents to re-output only JSON for the same batch files", () => {
    const prompt = buildInvestigateJsonRepairPrompt([
      { filePath: "apps/web/a.ts" } as any,
      { filePath: "lib/b.ts" } as any,
    ]);

    expect(prompt).toContain("previous response was not valid JSON");
    expect(prompt).toContain("Do not redo the investigation");
    expect(prompt).toContain("ONLY one valid JSON array");
    expect(prompt).toContain("- apps/web/a.ts");
    expect(prompt).toContain("- lib/b.ts");
    expect(prompt).toContain('"findings"');
  });

  it("asks revalidation agents to re-output only JSON verdicts", () => {
    const prompt = buildRevalidateJsonRepairPrompt();

    expect(prompt).toContain("previous response was not valid JSON");
    expect(prompt).toContain("Do not redo the revalidation");
    expect(prompt).toContain("ONLY one valid JSON array");
    expect(prompt).toContain('"verdict"');
    expect(prompt).toContain('"duplicateOf"');
  });

  it("preserves original and repair output in debug text when repair also fails", () => {
    const debug = formatJsonRepairFailureDebugText("Confirmed: no issue", "{ not json");

    expect(debug).toContain("# original malformed agent output");
    expect(debug).toContain("Confirmed: no issue");
    expect(debug).toContain("# JSON repair follow-up output");
    expect(debug).toContain("{ not json");
  });
});

/** A finding that passes `findingSchema` verbatim. */
function validFinding(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    severity: "HIGH",
    vulnSlug: "sql-injection",
    title: "SQL injection in user lookup",
    description: "Interpolates req.query.id into a raw query",
    lineNumbers: [10, 15],
    recommendation: "Use parameterized queries",
    confidence: "high",
    ...overrides,
  };
}

describe("parseInvestigateResults", () => {
  const batch = [{ filePath: "a.ts" } as any, { filePath: "b.ts" } as any];

  it("matches results to batch files; fills missing with empty findings", () => {
    const text = `\`\`\`json\n[{"filePath":"a.ts","findings":[${JSON.stringify(validFinding())}]}]\n\`\`\``;
    const out = parseInvestigateResults(text, batch);
    expect(out.results.find((r) => r.filePath === "a.ts")?.findings.length).toBe(1);
    expect(out.results.find((r) => r.filePath === "b.ts")?.findings).toEqual([]);
    expect(out.invalid).toEqual([]);
  });

  it("repairs common malformed model JSON before parsing findings", () => {
    const finding = JSON.stringify(validFinding({ description: "placeholder" }), null, 0).replace(
      '"description":"placeholder"',
      '"description":"Uses "signature !== expectedHash" comparison"',
    );
    const text = `Confirmed:\n\`\`\`json\n[{"filePath":"a.ts","findings":[${finding}]}`;

    const out = parseInvestigateResults(text, batch);

    expect(out.results.find((r) => r.filePath === "a.ts")?.findings[0]?.description).toBe(
      'Uses "signature !== expectedHash" comparison',
    );
    expect(out.results.find((r) => r.filePath === "b.ts")?.findings).toEqual([]);
  });

  it("throws on parse failure (fail-loud, never silently empty)", () => {
    // Silently returning empty findings on malformed JSON would mask
    // model truncation, prompt-injection-driven non-JSON output, and
    // gateway splices — all of which are indistinguishable from a
    // legitimate clean result. The processor's batch-level catch
    // converts this throw into batchesFailed++ + status=error.
    expect(() => parseInvestigateResults("not JSON at all", batch)).toThrow(
      /wasn't a parseable JSON findings array/,
    );
  });

  it("throws when the JSON parses but isn't an array", () => {
    expect(() => parseInvestigateResults('```json\n{"oops":"object"}\n```', batch)).toThrow(
      /not an array/,
    );
  });

  it("salvages valid findings and reports invalid ones instead of dropping the file", () => {
    // One bad enum used to poison the whole file record downstream: the
    // read-side schema rejected the record and every valid finding in it
    // vanished silently. Now the bad finding is carried out via `invalid`
    // for an in-session field repair.
    const findings = [
      validFinding(),
      validFinding({ title: "Bad severity", severity: "INFORMATIONAL" }),
      validFinding({ title: "Bad lineNumbers", lineNumbers: ["12"] }),
    ];
    const text = `\`\`\`json\n${JSON.stringify([{ filePath: "a.ts", findings }])}\n\`\`\``;

    const out = parseInvestigateResults(text, batch);

    const a = out.results.find((r) => r.filePath === "a.ts");
    expect(a?.findings.map((f) => f.title)).toEqual(["SQL injection in user lookup"]);
    expect(out.invalid).toHaveLength(2);
    expect(out.invalid[0].filePath).toBe("a.ts");
    expect(out.invalid[0].issues).toContain("severity");
    expect(out.invalid[1].issues).toContain("lineNumbers");
  });

  it("treats non-object findings as invalid", () => {
    const text = `\`\`\`json\n[{"filePath":"a.ts","findings":["oops"]}]\n\`\`\``;
    const out = parseInvestigateResults(text, batch);
    expect(out.results.find((r) => r.filePath === "a.ts")?.findings).toEqual([]);
    expect(out.invalid).toHaveLength(1);
  });
});

describe("buildInvestigateFieldRepairPrompt", () => {
  it("echoes each invalid finding with its validation errors", () => {
    const prompt = buildInvestigateFieldRepairPrompt([
      {
        filePath: "a.ts",
        raw: { severity: "INFO", title: "t" },
        issues: "severity: Invalid enum value",
      },
    ]);

    expect(prompt).toContain('filePath: "a.ts"');
    expect(prompt).toContain("severity: Invalid enum value");
    expect(prompt).toContain('"severity": "INFO"');
    expect(prompt).toContain("Do not redo the investigation");
    expect(prompt).toContain("do not repeat findings that were already accepted");
  });
});

describe("runInvestigateFieldRepairLoop", () => {
  const batch = [{ filePath: "a.ts" } as any];

  async function drive<T>(gen: AsyncGenerator<unknown, T>): Promise<{ ret: T; events: any[] }> {
    const events: any[] = [];
    let next = await gen.next();
    while (!next.done) {
      events.push(next.value);
      next = await gen.next();
    }
    return { ret: next.value, events };
  }

  it("merges repaired findings back into the kept results", async () => {
    const bad = validFinding({ title: "Fixed later", severity: "critical" });
    const fixed = validFinding({ title: "Fixed later", severity: "CRITICAL" });
    const prompts: string[] = [];

    const { ret } = await drive(
      runInvestigateFieldRepairLoop({
        results: [{ filePath: "a.ts", findings: [validFinding() as any] }],
        invalid: [{ filePath: "a.ts", raw: bad, issues: "severity: Invalid enum value" }],
        batch,
        followUp: async (p) => {
          prompts.push(p);
          return JSON.stringify([{ filePath: "a.ts", findings: [fixed] }]);
        },
        agentLabel: "Test",
        agentType: "test",
      }),
    );

    expect(prompts).toHaveLength(1);
    expect(ret.repairAttempts).toBe(1);
    const a = ret.results.find((r) => r.filePath === "a.ts");
    expect(a?.findings.map((f) => f.title).sort()).toEqual([
      "Fixed later",
      "SQL injection in user lookup",
    ]);
  });

  it("does not duplicate findings the model re-emits alongside the repair", async () => {
    const { ret } = await drive(
      runInvestigateFieldRepairLoop({
        results: [{ filePath: "a.ts", findings: [validFinding() as any] }],
        invalid: [{ filePath: "a.ts", raw: {}, issues: "severity: Required" }],
        batch,
        // Model ignores instructions and re-emits the already-accepted
        // finding too — signature dedup keeps exactly one copy.
        followUp: async () =>
          JSON.stringify([
            { filePath: "a.ts", findings: [validFinding(), validFinding({ title: "Repaired" })] },
          ]),
        agentLabel: "Test",
        agentType: "test",
      }),
    );

    const a = ret.results.find((r) => r.filePath === "a.ts");
    expect(a?.findings).toHaveLength(2);
  });

  it("drops still-invalid findings after maxRepairs and keeps the valid ones", async () => {
    const { ret, events } = await drive(
      runInvestigateFieldRepairLoop({
        results: [{ filePath: "a.ts", findings: [validFinding() as any] }],
        invalid: [
          { filePath: "a.ts", raw: { severity: "INFO" }, issues: "severity: Invalid enum value" },
        ],
        batch,
        // Repair keeps returning the same invalid finding.
        followUp: async () =>
          JSON.stringify([
            {
              filePath: "a.ts",
              findings: [validFinding({ severity: "INFO", title: "Still bad" })],
            },
          ]),
        agentLabel: "Test",
        agentType: "test",
        maxRepairs: 2,
      }),
    );

    expect(ret.repairAttempts).toBe(2);
    const a = ret.results.find((r) => r.filePath === "a.ts");
    expect(a?.findings.map((f) => f.title)).toEqual(["SQL injection in user lookup"]);
    expect(events.some((e) => /dropping 1 finding/.test(e.message))).toBe(true);
  });

  it("gives up cleanly when the follow-up returns undefined", async () => {
    const { ret } = await drive(
      runInvestigateFieldRepairLoop({
        results: [{ filePath: "a.ts", findings: [] }],
        invalid: [{ filePath: "a.ts", raw: {}, issues: "severity: Required" }],
        batch,
        followUp: async () => undefined,
        agentLabel: "Test",
        agentType: "test",
      }),
    );

    expect(ret.results.find((r) => r.filePath === "a.ts")?.findings).toEqual([]);
  });
});

describe("parseRevalidateVerdicts", () => {
  it("parses verdicts from fenced JSON", () => {
    const text =
      '```json\n[{"filePath":"a.ts","title":"x","verdict":"true-positive","reasoning":"r"}]\n```';
    const v = parseRevalidateVerdicts(text);
    expect(v).toHaveLength(1);
    expect(v[0].verdict).toBe("true-positive");
  });

  it("repairs common malformed model JSON before parsing verdicts", () => {
    const text =
      'Here are the verdicts:\n```json\n[{"filePath":"a.ts","title":"x","verdict":"true-positive","reasoning":"Line says "unsafe" but is mitigated",}]';

    const v = parseRevalidateVerdicts(text);

    expect(v).toHaveLength(1);
    expect(v[0].reasoning).toBe('Line says "unsafe" but is mitigated');
  });

  it("throws on parse failure", () => {
    expect(() => parseRevalidateVerdicts("garbage")).toThrow(/wasn't parseable JSON/);
  });
});

describe("writeParseFailureDebug", () => {
  let tmp: string;
  let prevDataRoot: string | undefined;
  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-debug-"));
    prevDataRoot = process.env.DEEPSEC_DATA_ROOT;
    process.env.DEEPSEC_DATA_ROOT = tmp;
  });
  afterEach(() => {
    if (prevDataRoot === undefined) delete process.env.DEEPSEC_DATA_ROOT;
    else process.env.DEEPSEC_DATA_ROOT = prevDataRoot;
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it("writes raw agent output to data/<projectId>/debug/parse-error-<phase>-<ts>.txt", () => {
    const written = writeParseFailureDebug({
      projectId: "demo",
      phase: "investigate",
      agentType: "claude-agent-sdk",
      resultText: "{ not valid json",
      error: new Error("Unexpected token n"),
      batch: [],
    });
    expect(written).toBeDefined();
    expect(written!).toMatch(/\/demo\/debug\/parse-error-investigate-.*\.txt$/);
    const body = fs.readFileSync(written!, "utf-8");
    expect(body).toContain("# phase: investigate");
    expect(body).toContain("# agentType: claude-agent-sdk");
    expect(body).toContain("Unexpected token n");
    expect(body).toContain("{ not valid json");
  });

  it("is a no-op without a projectId", () => {
    expect(
      writeParseFailureDebug({
        phase: "revalidate",
        agentType: "codex",
        resultText: "garbage",
        error: new Error("x"),
      }),
    ).toBeUndefined();
  });
});

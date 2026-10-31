import { describe, expect, it, vi } from "vitest";
import {
  type BenchmarkResult,
  buildRecommendedModelChoices,
  DEEPSEC_BENCHMARK_URL,
  fetchBenchmarkResults,
  inferModelHarness,
  resolveModelProfile,
} from "../auth/model-picker.js";

const results: BenchmarkResult[] = [
  {
    rank: 2,
    model: "gpt-5.6-sol",
    reasoning: "medium",
    modelId: "openai/gpt-5.6-sol",
    score: 20,
    cost: 10,
    harness: "codex",
  },
  {
    rank: 1,
    model: "gpt-5.6-sol",
    reasoning: "xhigh",
    modelId: "openai/gpt-5.6-sol",
    score: 35,
    cost: 50,
    harness: "codex",
  },
  {
    rank: 3,
    model: "claude-opus-5",
    reasoning: "max",
    modelId: "anthropic/claude-opus-5",
    score: 32,
    cost: 100,
    harness: "claude",
  },
  {
    rank: 4,
    model: "kimi-k3",
    reasoning: "high",
    modelId: "moonshotai/kimi-k3",
    score: 18,
    cost: 10,
    harness: "pi",
  },
  {
    rank: 5,
    model: "grok-4.5",
    reasoning: "medium",
    modelId: "xai/grok-4.5",
    score: 17,
    cost: 8,
    harness: "pi",
  },
  {
    rank: 6,
    model: "deepseek-v4-flash",
    reasoning: "high",
    modelId: "deepseek/deepseek-v4-flash",
    score: 16,
    cost: 5,
    harness: "pi",
  },
];

describe("DeepSecBench model picker", () => {
  it("infers provider-prefixed OpenAI and Anthropic slugs before generic Pi slugs", () => {
    expect(inferModelHarness("openai/gpt-5.6-sol")).toBe("codex");
    expect(inferModelHarness("anthropic/claude-opus-5")).toBe("claude");
    expect(inferModelHarness("xai/grok-4.5")).toBe("pi");
  });
  it("uses the highest-scoring combo for each recommendation and normalizes price", () => {
    const choices = buildRecommendedModelChoices(results);

    expect(choices.map((choice) => choice.label)).toEqual([
      "GPT-5.6 Sol",
      "Claude Opus 5",
      "Kimi K3",
      "Grok 4.5",
      "DeepSeek V4 Flash",
    ]);
    expect(choices[0]).toMatchObject({
      configuredModel: "gpt-5.6-sol",
      thinkingLevel: "xhigh",
      score: 35,
      relativePrice: 10,
    });
    expect(choices[1]).toMatchObject({ thinkingLevel: "xhigh", relativePrice: 20 });
    expect(choices[4]).toMatchObject({
      configuredModel: "deepseek/deepseek-v4-flash",
      relativePrice: 1,
    });
  });

  it("fetches the live leaderboard URL", async () => {
    const fetchImpl = vi.fn(
      async () => new Response(JSON.stringify({ results }), { status: 200 }),
    ) as unknown as typeof fetch;

    await expect(fetchBenchmarkResults(fetchImpl)).resolves.toEqual({ results, live: true });
    expect(fetchImpl).toHaveBeenCalledWith(
      DEEPSEC_BENCHMARK_URL,
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    );
  });

  it("falls back to the bundled snapshot when the leaderboard is unavailable", async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error("offline");
    }) as unknown as typeof fetch;

    const fallback = await fetchBenchmarkResults(fetchImpl);
    expect(fallback.live).toBe(false);
    expect(fallback.results).toHaveLength(5);
  });

  it("resolves best, value, and budget profiles from compatible live choices", async () => {
    const fetchImpl = vi.fn(
      async () => new Response(JSON.stringify({ results }), { status: 200 }),
    ) as unknown as typeof fetch;
    const route = { mode: "gateway" as const, provider: "vercel" };

    await expect(resolveModelProfile({ profile: "best", route, fetchImpl })).resolves.toMatchObject(
      {
        agent: "codex",
        model: "gpt-5.6-sol",
      },
    );
    await expect(
      resolveModelProfile({ profile: "value", route, fetchImpl }),
    ).resolves.toMatchObject({
      agent: "pi",
      model: "moonshotai/kimi-k3",
    });
    await expect(
      resolveModelProfile({ profile: "budget", route, fetchImpl }),
    ).resolves.toMatchObject({
      agent: "pi",
      model: "deepseek/deepseek-v4-flash",
    });
  });

  it("limits a profile to the harness supported by direct credentials", async () => {
    const fetchImpl = vi.fn(
      async () => new Response(JSON.stringify({ results }), { status: 200 }),
    ) as unknown as typeof fetch;

    await expect(
      resolveModelProfile({
        profile: "budget",
        route: { mode: "direct", provider: "anthropic" },
        fetchImpl,
      }),
    ).resolves.toMatchObject({ agent: "claude", model: "claude-opus-5" });
  });
});

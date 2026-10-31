import { createInterface } from "node:readline/promises";
import { BOLD, CYAN, DIM, RESET } from "../formatters.js";
import { SetupProtocolError } from "../setup/protocol.js";
import type { ModelRoute } from "./model-route.js";

export const DEEPSEC_BENCHMARK_URL =
  "https://vercel.com/ai-gateway/leaderboards/deepsecbench/results.json";

export type ModelHarness = "codex" | "claude" | "pi";

export interface BenchmarkResult {
  rank: number;
  model: string;
  reasoning: string;
  modelId: string;
  score: number;
  cost: number;
  harness: ModelHarness;
}

export interface RecommendedModelChoice extends BenchmarkResult {
  label: string;
  agent: ModelHarness;
  configuredModel: string;
  thinkingLevel?: string;
  relativePrice: number;
}

export interface InteractiveModelSelection {
  agent: ModelHarness;
  model: string;
  thinkingLevel?: string;
}

export type ModelProfile = "best" | "value" | "budget";

const FALLBACK_RESULTS: BenchmarkResult[] = [
  {
    rank: 1,
    model: "gpt-5.6-sol",
    reasoning: "xhigh",
    modelId: "openai/gpt-5.6-sol",
    score: 35.57947623262352,
    cost: 55.977321,
    harness: "codex",
  },
  {
    rank: 2,
    model: "claude-opus-5",
    reasoning: "max",
    modelId: "anthropic/claude-opus-5",
    score: 32.56825950279352,
    cost: 127.92943925,
    harness: "claude",
  },
  {
    rank: 8,
    model: "kimi-k3",
    reasoning: "high",
    modelId: "moonshotai/kimi-k3",
    score: 17.56002233389168,
    cost: 12.37509965,
    harness: "pi",
  },
  {
    rank: 12,
    model: "grok-4.5",
    reasoning: "medium",
    modelId: "xai/grok-4.5",
    score: 16.535137166478766,
    cost: 11.0445542,
    harness: "pi",
  },
  {
    rank: 10,
    model: "deepseek-v4-flash",
    reasoning: "high",
    modelId: "deepseek/deepseek-v4-flash",
    score: 16.541857605901416,
    cost: 5.9404634588,
    harness: "pi",
  },
];

const LABELS: Record<string, string> = {
  "openai/gpt-5.6-sol": "GPT-5.6 Sol",
  "anthropic/claude-opus-5": "Claude Opus 5",
  "moonshotai/kimi-k3": "Kimi K3",
  "xai/grok-4.5": "Grok 4.5",
  "deepseek/deepseek-v4-flash": "DeepSeek V4 Flash",
};

const PREFERRED_MODELS = [
  "openai/gpt-5.6-sol",
  "anthropic/claude-opus-5",
  "moonshotai/kimi-k3",
  "xai/grok-4.5",
  "deepseek/deepseek-v4-flash",
] as const;

function isBenchmarkResult(value: unknown): value is BenchmarkResult {
  if (!value || typeof value !== "object") return false;
  const result = value as Record<string, unknown>;
  return (
    typeof result.rank === "number" &&
    typeof result.model === "string" &&
    typeof result.reasoning === "string" &&
    typeof result.modelId === "string" &&
    typeof result.score === "number" &&
    typeof result.cost === "number" &&
    (result.harness === "codex" || result.harness === "claude" || result.harness === "pi")
  );
}

export async function fetchBenchmarkResults(
  fetchImpl: typeof fetch = fetch,
): Promise<{ results: BenchmarkResult[]; live: boolean }> {
  try {
    const response = await fetchImpl(DEEPSEC_BENCHMARK_URL, {
      signal: AbortSignal.timeout(5_000),
    });
    if (!response.ok) throw new Error(`DeepSecBench returned HTTP ${response.status}`);
    const payload = (await response.json()) as { results?: unknown[] };
    const results = (payload.results ?? []).filter(isBenchmarkResult);
    if (results.length === 0) throw new Error("DeepSecBench returned no usable results");
    return { results, live: true };
  } catch {
    return { results: FALLBACK_RESULTS, live: false };
  }
}

function strongest(results: BenchmarkResult[], modelId: string): BenchmarkResult | undefined {
  return results
    .filter((result) => result.modelId === modelId)
    .sort((left, right) => right.score - left.score)[0];
}

function configuredModel(result: BenchmarkResult): string {
  return result.harness === "pi" ? result.modelId : result.model;
}

function thinkingLevel(reasoning: string): string | undefined {
  if (reasoning === "default") return undefined;
  return reasoning === "max" ? "xhigh" : reasoning;
}

export function buildRecommendedModelChoices(results: BenchmarkResult[]): RecommendedModelChoice[] {
  const selected = PREFERRED_MODELS.map(
    (modelId) => strongest(results, modelId) ?? strongest(FALLBACK_RESULTS, modelId),
  ).filter((result): result is BenchmarkResult => result !== undefined);
  const cheapest = Math.min(...selected.map((result) => result.cost));
  return selected.map((result) => ({
    ...result,
    label: LABELS[result.modelId] ?? result.model,
    agent: result.harness,
    configuredModel: configuredModel(result),
    thinkingLevel: thinkingLevel(result.reasoning),
    relativePrice: result.cost / cheapest,
  }));
}

function canonicalHarness(value: string | undefined): ModelHarness | undefined {
  if (value === "claude-agent-sdk" || value === "claude") return "claude";
  if (value === "codex" || value === "pi") return value;
  return undefined;
}

function compatibleHarness(route: ModelRoute, requested?: string): ModelHarness | undefined {
  if (route.mode === "direct") return route.provider === "anthropic" ? "claude" : "codex";
  if (route.mode === "custom") return "pi";
  return canonicalHarness(requested);
}

export function parseModelProfile(value: string | undefined): ModelProfile | undefined {
  if (value === undefined) return undefined;
  if (value === "best" || value === "value" || value === "budget") return value;
  throw new SetupProtocolError({
    code: "INVALID_MODEL_PROFILE",
    kind: "failure",
    message: "--model-profile must be best, value, or budget",
  });
}

export async function resolveModelProfile(options: {
  profile: ModelProfile;
  route: ModelRoute;
  agent?: string;
  fetchImpl?: typeof fetch;
}): Promise<
  InteractiveModelSelection & {
    profile: ModelProfile;
    score: number;
    relativePrice: number;
    live: boolean;
    label: string;
  }
> {
  const benchmark = await fetchBenchmarkResults(options.fetchImpl);
  const requiredHarness = compatibleHarness(options.route, options.agent);
  const choices = buildRecommendedModelChoices(benchmark.results).filter(
    (choice) => !requiredHarness || choice.agent === requiredHarness,
  );
  const byScore = [...choices].sort((left, right) => right.score - left.score);
  const selected =
    options.profile === "best"
      ? byScore[0]
      : options.profile === "budget"
        ? [...choices].sort((left, right) => left.cost - right.cost)[0]
        : (byScore.find((choice) => choice.relativePrice <= 2.5) ?? byScore[0]);
  if (!selected) {
    throw new SetupProtocolError({
      code: "MODEL_PROFILE_UNAVAILABLE",
      kind: "failure",
      message: `No ${options.profile} model is compatible with the selected credential route`,
    });
  }
  return {
    profile: options.profile,
    agent: selected.agent,
    model: selected.configuredModel,
    thinkingLevel: selected.thinkingLevel,
    score: selected.score,
    relativePrice: selected.relativePrice,
    live: benchmark.live,
    label: selected.label,
  };
}

export function inferModelHarness(slug: string): ModelHarness {
  if (/^(?:openai\/)?gpt-/i.test(slug)) return "codex";
  if (/^(?:anthropic\/)?claude-/i.test(slug)) return "claude";
  if (slug.includes("/")) return "pi";
  return "pi";
}

function modelForHarness(slug: string, harness: ModelHarness): string {
  if (harness === "codex" && slug.startsWith("openai/")) return slug.slice("openai/".length);
  if (harness === "claude" && slug.startsWith("anthropic/")) {
    return slug.slice("anthropic/".length);
  }
  return slug;
}

function displayHarness(harness: ModelHarness): string {
  if (harness === "claude") return "Claude";
  if (harness === "codex") return "Codex";
  return "Pi";
}

function formatRelativePrice(value: number): string {
  return value < 1.05 ? "1×" : `${value.toFixed(1)}×`;
}

export async function promptForModelSelection(options: {
  route: ModelRoute;
  agent?: string;
  fetchImpl?: typeof fetch;
}): Promise<InteractiveModelSelection> {
  console.log("\nChoose the model Deepsec should use:");
  console.log(`  ${DIM}Loading current DeepSecBench recommendations…${RESET}`);
  const benchmark = await fetchBenchmarkResults(options.fetchImpl);
  const requiredHarness = compatibleHarness(options.route, options.agent);
  const recommendations = buildRecommendedModelChoices(benchmark.results);
  const choices = recommendations.filter(
    (choice) => !requiredHarness || choice.agent === requiredHarness,
  );
  const prompt = createInterface({ input: process.stdin, output: process.stdout });
  try {
    if (choices.length < recommendations.length) {
      console.log(
        `  ${DIM}Showing ${displayHarness(requiredHarness!)} models compatible with the selected credential route.${RESET}`,
      );
    }
    for (const [index, choice] of choices.entries()) {
      console.log(
        `  ${index + 1}. ${BOLD}${choice.label}${RESET} · ${displayHarness(choice.agent)} · ${choice.reasoning}  ${CYAN}score ${choice.score.toFixed(2)}${RESET}  price ${formatRelativePrice(choice.relativePrice)}`,
      );
    }
    const customIndex = choices.length + 1;
    console.log(`  ${customIndex}. Paste a custom model slug`);
    console.log(
      `  ${DIM}DeepSecBench score; price is total benchmark-run cost relative to the cheapest recommendation. ${benchmark.live ? "Live data." : "Cached fallback data."}${RESET}`,
    );
    const answer = (await prompt.question("\nModel [1]: ")).trim() || "1";
    const selected = Number(answer);
    if (Number.isInteger(selected) && selected >= 1 && selected <= choices.length) {
      const choice = choices[selected - 1];
      return {
        agent: choice.agent,
        model: choice.configuredModel,
        thinkingLevel: choice.thinkingLevel,
      };
    }
    if (selected !== customIndex) throw new Error("Invalid model selection");

    const slug = (await prompt.question("Model slug: ")).trim();
    if (!slug || /\s/.test(slug)) {
      throw new Error("Model slug must be a non-empty value without spaces");
    }
    let agent = requiredHarness ?? inferModelHarness(slug);
    if (!requiredHarness) {
      const harnessAnswer = (
        await prompt.question(`Agent harness (codex, claude, pi) [${agent}]: `)
      ).trim();
      const selectedHarness = canonicalHarness(harnessAnswer || agent);
      if (!selectedHarness) throw new Error("Agent harness must be codex, claude, or pi");
      agent = selectedHarness;
    }
    const level = (await prompt.question("Thinking level [medium]: ")).trim() || "medium";
    if (!["minimal", "low", "medium", "high", "xhigh"].includes(level)) {
      throw new Error("Thinking level must be minimal, low, medium, high, or xhigh");
    }
    return { agent, model: modelForHarness(slug, agent), thinkingLevel: level };
  } finally {
    prompt.close();
  }
}

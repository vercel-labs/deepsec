import { createInterface } from "node:readline/promises";
import type { ModelRoute } from "./model-route.js";

export interface InteractiveModelChoice {
  route: ModelRoute;
  defaultAgent?: "codex" | "claude";
}

export async function promptForModelRoute(): Promise<InteractiveModelChoice> {
  const prompt = createInterface({ input: process.stdin, output: process.stdout });
  try {
    console.log("\nChoose how Deepsec should access an AI model:");
    console.log("  1. Vercel AI Gateway using the linked project's identity (recommended)");
    console.log("  2. My OpenAI API key");
    console.log("  3. My Anthropic API key");
    console.log("  4. Use local subscriptions (claude/codex already logged in on this machine)");
    const answer = (await prompt.question("\nModel access [1]: ")).trim() || "1";
    if (answer === "1") return { route: { mode: "gateway", provider: "vercel" } };
    if (answer === "4") return { route: { mode: "local", provider: "local" } };
    if (answer !== "2" && answer !== "3") throw new Error("Invalid model access selection");
    const openai = answer === "2";
    const defaultEnv = openai ? "OPENAI_API_KEY" : "ANTHROPIC_API_KEY";
    const envAnswer = await prompt.question(`Credential environment variable [${defaultEnv}]: `);
    const apiKeyEnv = envAnswer.trim() || defaultEnv;
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(apiKeyEnv)) {
      throw new Error("Credential environment variable must be a valid environment-variable name");
    }
    return {
      route: {
        mode: "direct",
        provider: openai ? "openai" : "anthropic",
        apiKeyEnv,
      },
      defaultAgent: openai ? "codex" : "claude",
    };
  } finally {
    prompt.close();
  }
}

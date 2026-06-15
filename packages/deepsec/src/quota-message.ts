// Renders the message we print when a process/revalidate run is stopped
// because the agent's upstream credential ran out of quota or credits.
//
// The message text is tailored along two axes:
//   1. *Source* of the exhausted credential — subscription (Claude Pro /
//      ChatGPT Plus), direct provider key (Anthropic / OpenAI), or AI
//      Gateway. Determines what the user actually has to do.
//   2. *Whether the run is already on AI Gateway* — if it is, we never
//      tell them to "switch to AI Gateway"; instead we point them at the
//      gateway top-up flow.
//
// The classifier sits in the processor package
// (`classifyQuotaError` → `QuotaSource`); the gateway-detection helper
// (`isUsingAiGateway`) is also there so it can be reused by tests and
// downstream consumers without importing the CLI.

import { isUsingAiGateway, type QuotaSource } from "@deepsec/processor";
import { BOLD, DIM, RED, RESET, YELLOW } from "./formatters.js";

// Top-level setup doc — already used by preflight.ts. Kept identical here
// so the message stays consistent across credential failures and quota
// failures.
const SETUP_DOC_URL = "https://github.com/vercel-labs/deepsec/blob/main/docs/vercel-setup.md";
// Canonical AI Gateway top-up deep link — exactly the URL the gateway
// itself embeds in its `insufficient_funds` (HTTP 402) error response
// (see vercel/ai-gateway/lib/gateway/check-billing.ts:44). Lands on the
// AI dashboard with the top-up modal pre-opened, so the user is one
// click from adding credit. Mirroring the gateway's own choice keeps the
// remediation consistent if a user got the upstream error before us.
const AI_GATEWAY_TOPUP_URL = "https://vercel.com/d?to=%2F%5Bteam%5D%2F%7E%2Fai%3Fmodal%3Dtop-up";
// Pricing/top-up doc for users who want the long-form explanation
// (auto-top-up configuration, free vs paid tier, etc.).
const AI_GATEWAY_TOPUP_DOC_URL =
  "https://vercel.com/docs/ai-gateway/pricing#top-up-your-ai-gateway-credits";

function sourceLabel(source: QuotaSource): string {
  switch (source) {
    case "claude-subscription":
      return "Claude Pro/Max subscription";
    case "anthropic-credits":
      return "Anthropic API credits";
    case "cursor-quota":
      return "Cursor API quota";
    case "openai-quota":
      return "OpenAI API quota";
    case "openai-subscription":
      return "ChatGPT subscription";
    case "gateway-credits":
      return "Vercel AI Gateway credits";
    case "unknown":
      return "AI provider quota";
  }
}

/**
 * Build the multi-line, ANSI-colored block we print on stderr/stdout when
 * a run stops because of quota exhaustion. Returns plain text — the
 * caller is responsible for `console.log`-ing it. Splitting render from
 * print keeps unit tests simple (no stdout capture needed).
 */
export function renderQuotaMessage(args: {
  source: QuotaSource;
  rawMessage: string;
  /** "process" or "revalidate" — used in the header and the rerun command hint */
  command: "process" | "revalidate";
  projectId: string;
}): string {
  const { source, rawMessage, command, projectId } = args;
  const onGateway = isUsingAiGateway();
  const lines: string[] = [];

  lines.push("");
  lines.push(`${RED}${BOLD}✘ Stopped: ${sourceLabel(source)} exhausted${RESET}`);

  // Body — branches on whether the user is already routing through the
  // gateway. We never tell a gateway user to "switch to gateway."
  if (onGateway || source === "gateway-credits") {
    lines.push("");
    lines.push("  Your Vercel AI Gateway balance is empty. Add credits or enable");
    lines.push("  auto-top-up:");
    lines.push("");
    lines.push(`    Top up now:  ${AI_GATEWAY_TOPUP_URL}`);
    lines.push(`    Pricing:     ${AI_GATEWAY_TOPUP_DOC_URL}`);
  } else if (source === "claude-subscription" || source === "openai-subscription") {
    lines.push("");
    lines.push(
      `  ${YELLOW}Subscriptions (Claude Pro/Max, ChatGPT Plus) are useful for evaluating${RESET}`,
    );
    lines.push(
      `  ${YELLOW}deepsec but generally do not have enough headroom for full repo scans.${RESET}`,
    );
    lines.push("");
    lines.push(`  ${BOLD}Recommended: switch to Vercel AI Gateway.${RESET}`);
    lines.push("");
    lines.push(`    ${DIM}# from your repo root${RESET}`);
    lines.push("    npx vercel link");
    lines.push("    npx vercel env pull");
    lines.push("");
    lines.push(`  Or set ${BOLD}AI_GATEWAY_API_KEY=vck_…${RESET} in .env.local.`);
    lines.push(`  Setup: ${SETUP_DOC_URL}`);
  } else if (source === "cursor-quota") {
    lines.push("");
    lines.push("  Your Cursor API key hit a usage or billing limit.");
    lines.push("");
    lines.push("  Check your Cursor dashboard or team billing, then rerun the command.");
    lines.push("  If you want AI Gateway-backed billing, switch to the claude/codex backend.");
  } else {
    // anthropic-credits / openai-quota / unknown
    const accountPhrase =
      source === "anthropic-credits"
        ? "Your direct Anthropic account"
        : source === "openai-quota"
          ? "Your direct OpenAI account"
          : "Your AI provider account";
    lines.push("");
    lines.push(`  ${accountPhrase} is out of credits/quota.`);
    lines.push("");
    lines.push(`  Either top up that account, or switch to ${BOLD}Vercel AI Gateway${RESET}`);
    lines.push("  for unified billing and observability:");
    lines.push("");
    lines.push("    npx vercel link");
    lines.push("    npx vercel env pull");
    lines.push("");
    lines.push(`  Setup: ${SETUP_DOC_URL}`);
  }

  // Always tail with the upstream's verbatim message — at most one short
  // line — so a power user can see what actually came back. Multi-line
  // upstream errors get squashed to keep the block tidy.
  const tail = rawMessage.replace(/\s+/g, " ").trim().slice(0, 200);
  if (tail) {
    lines.push("");
    lines.push(`  ${DIM}Upstream: ${tail}${RESET}`);
  }

  // Re-run hint so the user has something obvious to copy after fixing.
  lines.push("");
  lines.push(`  ${DIM}After fixing, re-run:  deepsec ${command} --project-id ${projectId}${RESET}`);
  lines.push("");

  return lines.join("\n");
}

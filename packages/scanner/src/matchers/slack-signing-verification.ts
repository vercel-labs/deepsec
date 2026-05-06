import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Slack-bound endpoint handlers. Slack signs every request with HMAC-SHA256
 * keyed by the signing secret. Failure modes:
 *   - Verification missing entirely
 *   - Verification using `==` / `===` instead of `crypto.timingSafeEqual`
 *   - Timestamp not checked (replay)
 *   - Body parsed before HMAC computed (HMAC of parsed body != HMAC of raw bytes)
 *   - Verification AFTER tool dispatch / DB write
 *
 * `@slack/bolt` does verification internally if you use its receivers, but
 * raw Next.js route handlers (`app/api/.../route.ts`) need to do it
 * themselves. This matcher flags Slack-handler files so each one can be
 * audited.
 */
export const slackSigningVerificationMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "slack-signing-verification",
  description: "Slack request handlers — verify HMAC signing + replay protection",
  filePatterns: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.mjs"],
  examples: [
    `import { App } from "@slack/bolt";\nexport async function POST(req: Request) {\n  return new Response("ok");\n}`,
    `import { App } from "@slack/bolt";\nconst app = new App({ signingSecret: process.env.SLACK_SIGNING_SECRET });`,
    `import { App } from "@slack/bolt";\napp.command("/hello", async ({ ack }) => { await ack(); });`,
    `import { App } from "@slack/bolt";\napp.action("button_click", async ({ ack }) => { await ack(); });`,
    `import { App } from "@slack/bolt";\napp.event("message", async ({ event }) => {});`,
    `import { App } from "@slack/bolt";\napp.view("modal_submit", async ({ ack }) => { await ack(); });`,
    `import { App } from "@slack/bolt";\napp.shortcut("global_shortcut", async ({ ack }) => { await ack(); });`,
    `import { AwsLambdaReceiver } from "@slack/bolt";\nconst receiver = new AwsLambdaReceiver({ signingSecret: "x" });`,
    `import { verifySlackRequest } from "@slack/web-api";\nverifySlackRequest({ body, signingSecret });`,
    `import { createHmac } from "crypto";\nconst SLACK_SIGNING_SECRET = process.env.SLACK_SIGNING_SECRET;\nconst hmac = crypto.createHmac("sha256", slackSecret);`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)$/.test(filePath)) return [];
    if (/\.d\.ts$/.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];

    const HAS_SLACK =
      /\bfrom\s+["'](?:@slack\/(?:bolt|web-api|events-api|interactive-messages|oauth)|slack-bolt)["']|\bSlackRequestVerifier\b|\bverifySlackRequest\b|\bslack_signing_secret\b|\bSLACK_SIGNING_SECRET\b/;
    const PATH_HINT =
      /(?:^|\/)(?:slack|bolt)(?:[-_./]|$)|\/slack-events|\/slack-actions|\/slack-commands|\/slack-interactivity/i;
    if (!HAS_SLACK.test(content) && !PATH_HINT.test(filePath)) return [];

    const lines = content.split("\n");
    const matches: CandidateMatch[] = [];

    // Look for Slack endpoint handlers
    const HANDLER_PATTERNS: { regex: RegExp; label: string }[] = [
      {
        regex: /\bexport\s+(?:async\s+)?function\s+(?:POST|GET|handle)\b/,
        label: "Slack-context HTTP handler",
      },
      {
        regex: /\bnew\s+App\s*\(\s*\{[^}]*signingSecret\s*:/m,
        label: "Slack Bolt App construction",
      },
      { regex: /\bapp\.\s*command\s*\(/, label: "Slack Bolt slash-command handler" },
      { regex: /\bapp\.\s*action\s*\(/, label: "Slack Bolt action handler" },
      { regex: /\bapp\.\s*event\s*\(/, label: "Slack Bolt event handler" },
      { regex: /\bapp\.\s*view\s*\(/, label: "Slack Bolt view (modal) handler" },
      { regex: /\bapp\.\s*shortcut\s*\(/, label: "Slack Bolt shortcut handler" },
      {
        regex: /\bawsLambdaReceiver\b|\bExpressReceiver\b|\bAwsLambdaReceiver\b/,
        label: "Slack Bolt receiver wiring",
      },
      { regex: /\bverifySlackRequest\s*\(/, label: "Manual Slack signature verification" },
      {
        regex: /\bcrypto\.\s*createHmac\s*\(\s*["']sha256["'].*?(?:slack|signing)/i,
        label: "Slack HMAC-SHA256 verification",
      },
    ];

    for (let i = 0; i < lines.length; i++) {
      for (const { regex, label } of HANDLER_PATTERNS) {
        if (regex.test(lines[i])) {
          const start = Math.max(0, i - 1);
          const end = Math.min(lines.length, i + 6);
          matches.push({
            vulnSlug: "slack-signing-verification",
            lineNumbers: [i + 1],
            snippet: lines.slice(start, end).join("\n"),
            matchedPattern: label,
          });
          break;
        }
      }
    }
    return matches;
  },
};

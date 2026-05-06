import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Server-Action handler entry-point matcher. Flags the framework code that
 * receives `__Next-Action` requests, looks up the action by ID, deserializes
 * the args, invokes the user function, and serializes the result back into
 * the RSC stream.
 *
 * Concrete spots flagged include `app-render/action-handler.ts`,
 * `app-render/action-async-storage.ts`, the action-encryption utilities, and
 * any decode/parseAction helpers.
 */
export const frameworkServerActionMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "framework-server-action",
  description: "Server Action dispatcher / encoder / decoder code in the framework",
  filePatterns: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.mjs"],
  requires: { tech: ["nextjs"] },
  examples: [
    `const result = decodeReply(body, manifest);`,
    `const args = await decodeAction(formData, serverModuleMap);`,
    `const state = decodeFormState(rawState, formData);`,
    `const stream = encodeReply(value);`,
    `const action = parseAction(request);`,
    `const fn = getActionFromManifest(actionId, manifest);`,
    `await callServer(actionId, args);`,
    `const id = parseActionId(headers.get('next-action'));`,
    `registerServerReference(actionFn, actionId, null);`,
    `const header = req.headers['__Next-Action'];`,
    `const id = req.headers.get('next-action-id');`,
    `if (action.id === actionId) { /* dispatch */ }`,
    `import actionManifest from './actions.json'`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)$/.test(filePath)) return [];
    if (/\.d\.ts$/.test(filePath)) return [];

    const PATH_HINT =
      /(?:^|\/)action-(?:handler|async-storage|encryption|utils|errors)\.[tj]sx?$|(?:^|\/)server-actions?\.[tj]sx?$|(?:^|\/)decodeAction\.|(?:^|\/)decodeReply\./;
    const CONTENT_HINTS = [
      /\b(?:decodeReply|decodeAction|decodeFormState|encodeReply|parseAction|getActionFromManifest|callServer|parseActionId|registerServerReference)\s*\(/,
      /\b__Next[-_]Action\b/,
      /\b['"]next-action(?:-id|-redirect)?['"]/,
      /\baction\.id\s*===|actionManifest\b|actions\.json\b/,
    ];

    const isHandlerByPath = PATH_HINT.test(filePath);
    const lines = content.split("\n");
    const hitLines: number[] = [];
    const labels = new Set<string>();
    let firstContext: string | undefined;

    for (let i = 0; i < lines.length; i++) {
      let matched = false;
      for (const re of CONTENT_HINTS) {
        if (re.test(lines[i])) {
          matched = true;
          labels.add(re.source.slice(0, 40));
          break;
        }
      }
      if (!matched) continue;
      hitLines.push(i + 1);
      if (firstContext === undefined) {
        const s = Math.max(0, i - 2);
        const e = Math.min(lines.length, i + 4);
        firstContext = lines.slice(s, e).join("\n");
      }
    }

    if (hitLines.length === 0 && isHandlerByPath) {
      const match: CandidateMatch = {
        vulnSlug: "framework-server-action",
        lineNumbers: [1],
        snippet: lines.slice(0, 5).join("\n"),
        matchedPattern: "action handler file (path)",
      };
      return [match];
    }

    if (hitLines.length === 0) return [];
    const match: CandidateMatch = {
      vulnSlug: "framework-server-action",
      lineNumbers: hitLines,
      snippet: firstContext ?? "",
      matchedPattern: Array.from(labels).slice(0, 3).join(", "),
    };
    return [match];
  },
};

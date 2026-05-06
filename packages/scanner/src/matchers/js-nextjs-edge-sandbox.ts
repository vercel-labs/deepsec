import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * The Next.js Edge runtime sandbox. The framework executes user middleware /
 * Edge route handlers in a V8 isolate emulator with shimmed Node globals.
 * Anywhere `Buffer`, `process`, `crypto`, `fetch`, `URL`, `globalThis` is
 * shimmed for that runtime, the shim must be careful not to leak the host
 * Node capabilities into Edge code paths.
 *
 * Flags entry-point files under `server/web/sandbox/*`, `web-server.ts`,
 * `web-runtime/`, plus `eval`/`new Function` patterns and Buffer/process
 * shim code in those directories.
 */
export const frameworkEdgeSandboxMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "framework-edge-sandbox",
  description: "Edge runtime sandbox + global shims (Buffer/process/fetch leak risk)",
  filePatterns: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.mjs"],
  requires: { tech: ["nextjs"] },
  examples: [
    `const fn = new Function('a', 'return a + 1');`,
    `const result = eval(userCode);`,
    `await context.evaluate(moduleSource);`,
    `const script = new vm.Script(code);`,
    `vm.runInNewContext(code, sandbox);`,
    `vm.runInContext(code, ctx);`,
    `const ctx = vm.createContext({});`,
    `globalThis.Buffer = Buffer;`,
    `self.process = process;`,
    `globalThis.fetch = fetch;`,
    `// edge-runtime polyfill setup`,
    `const bindings = createBindings(env);`,
    `const wrapper = buildSandboxFunction(source);`,
    `const buf = Buffer as any;`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)$/.test(filePath)) return [];
    if (/\.d\.ts$/.test(filePath)) return [];

    const PATH_HINT =
      /(?:^|\/)server\/web\/sandbox\/|(?:^|\/)server\/web\/(?:web-runtime|spec-extension|spec-compliant)\/|(?:^|\/)server\/(?:next-base-server|web-server)\.[tj]sx?$|(?:^|\/)server\/web\/edge-route-module-wrapper\.[tj]sx?$/;
    const CONTENT_HINTS = [
      /\bnew\s+Function\s*\(/,
      /\beval\s*\(/,
      /\bcontext\.evaluate\s*\(/,
      /\bvm\.(?:Script|runInNewContext|runInContext|createContext)\s*\(/,
      /\b(?:globalThis|self)\.(?:Buffer|process|require|fetch)\s*=/,
      /\bedge-?runtime\b/i,
      /\bcreateBindings\s*\(|\bbuildSandboxFunction\s*\(/,
      /\bBuffer\s*as\s*any\b/,
    ];

    const isByPath = PATH_HINT.test(filePath);
    const lines = content.split("\n");
    const hitLines: number[] = [];
    const labels = new Set<string>();
    let firstContext: string | undefined;

    for (let i = 0; i < lines.length; i++) {
      for (const re of CONTENT_HINTS) {
        if (re.test(lines[i])) {
          hitLines.push(i + 1);
          labels.add(re.source.slice(0, 40));
          if (firstContext === undefined) {
            const s = Math.max(0, i - 2);
            const e = Math.min(lines.length, i + 3);
            firstContext = lines.slice(s, e).join("\n");
          }
          break;
        }
      }
    }

    if (hitLines.length === 0 && isByPath) {
      const match: CandidateMatch = {
        vulnSlug: "framework-edge-sandbox",
        lineNumbers: [1],
        snippet: lines.slice(0, 5).join("\n"),
        matchedPattern: "edge sandbox file (path)",
      };
      return [match];
    }
    if (hitLines.length === 0) return [];
    const match: CandidateMatch = {
      vulnSlug: "framework-edge-sandbox",
      lineNumbers: hitLines,
      snippet: firstContext ?? "",
      matchedPattern: Array.from(labels).slice(0, 3).join(", "),
    };
    return [match];
  },
};

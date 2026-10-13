import fs from "node:fs";
import path from "node:path";
import type { ModelRoute } from "../auth/model-route.js";

const GENERATED_IMPORT = 'import { generatedMatchersPlugin } from "./generated-matchers.js";';
const ROUTE_MARKER = "// <deepsec:model-route>";
const AGENT_MARKER = "// <deepsec:default-agent>";
const MODEL_MARKER = "// <deepsec:default-model>";
const THINKING_MARKER = "// <deepsec:default-thinking-level>";

function upsertConfigLine(
  source: string,
  options: {
    key: string;
    value: string;
    marker: string;
  },
): string {
  const line = `${options.key}: ${JSON.stringify(options.value)}, ${options.marker}`;
  if (source.includes(options.marker)) {
    return source.replace(new RegExp(`^\\s*${options.key}:.*$`, "m"), `  ${line}`);
  }
  return source.replace(/defineConfig\(\{\s*/, (match) => `${match}${line}\n  `);
}

function upsertRouteLine(source: string, route: ModelRoute): string {
  const line = `ai: ${JSON.stringify(route)}, ${ROUTE_MARKER}`;
  if (source.includes(ROUTE_MARKER)) {
    return source.replace(/^\s*ai:.*<deepsec:model-route>.*$/m, `  ${line}`);
  }
  return source.replace(/defineConfig\(\{\s*/, (match) => `${match}${line}\n  `);
}

/**
 * Record the selected route in the generated config before any interruptible
 * setup work runs. Setup only records its own checkpoint once login succeeds,
 * and init only prompts for a route on a first run, so without this an
 * interrupt in between loses the choice.
 */
export function persistWorkspaceConfigRoute(workspaceDir: string, route: ModelRoute): void {
  const file = path.join(workspaceDir, "deepsec.config.ts");
  fs.writeFileSync(file, upsertRouteLine(fs.readFileSync(file, "utf8"), route));
}

/** Route recorded by {@link persistWorkspaceConfigRoute} or a previous setup run. */
export function readWorkspaceConfigRoute(workspaceDir: string): ModelRoute | undefined {
  let source: string;
  try {
    source = fs.readFileSync(path.join(workspaceDir, "deepsec.config.ts"), "utf8");
  } catch {
    return undefined;
  }
  const match = source.match(/^\s*ai:\s*(.*),\s*\/\/ <deepsec:model-route>/m);
  if (!match) return undefined;
  try {
    const route = JSON.parse(match[1]) as ModelRoute;
    if (typeof route?.mode !== "string" || typeof route.provider !== "string") return undefined;
    return route;
  } catch {
    // A hand-edited route line is not authoritative; fall back to prompting.
    return undefined;
  }
}

/** Idempotently migrate older generated workspaces to the one-shot config hooks. */
export function reconcileWorkspaceConfig(
  workspaceDir: string,
  route: ModelRoute,
  agentType: string,
  model: string,
  thinkingLevel?: string,
): void {
  const file = path.join(workspaceDir, "deepsec.config.ts");
  let source = fs.readFileSync(file, "utf8");

  if (!source.includes("generatedMatchersPlugin")) {
    source = `${GENERATED_IMPORT}\n${source}`;
    if (/\bplugins\s*:\s*\[/.test(source)) {
      source = source.replace(/\bplugins\s*:\s*\[/, "plugins: [generatedMatchersPlugin, ");
    } else {
      source = source.replace(
        /defineConfig\(\{\s*/,
        (match) => `${match}plugins: [generatedMatchersPlugin],\n  `,
      );
    }
  }

  source = upsertRouteLine(source, route);

  const agentLine = `defaultAgent: ${JSON.stringify(agentType)}, ${AGENT_MARKER}`;
  if (source.includes(AGENT_MARKER)) {
    source = source.replace(/^\s*defaultAgent:.*<deepsec:default-agent>.*$/m, `  ${agentLine}`);
  } else if (/^\s*defaultAgent\s*:/m.test(source)) {
    source = source.replace(/^\s*defaultAgent\s*:.*$/m, `  ${agentLine}`);
  } else {
    source = source.replace(/defineConfig\(\{\s*/, (match) => `${match}${agentLine}\n  `);
  }
  source = upsertConfigLine(source, { key: "defaultModel", value: model, marker: MODEL_MARKER });
  if (thinkingLevel) {
    source = upsertConfigLine(source, {
      key: "defaultThinkingLevel",
      value: thinkingLevel,
      marker: THINKING_MARKER,
    });
  } else if (source.includes(THINKING_MARKER)) {
    source = source.replace(
      /^\s*defaultThinkingLevel:.*<deepsec:default-thinking-level>.*\n?/m,
      "",
    );
  }
  fs.writeFileSync(file, source);
}

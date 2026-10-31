import fs from "node:fs";
import path from "node:path";
import { type AgentProgress, runSetupTask } from "@deepsec/processor";
import {
  compileDeclarativeMatchers,
  type DeclarativeMatcherPlugin,
  type DeclarativeMatcherSpec,
} from "@deepsec/scanner";
import { atomicWriteFileSync } from "../atomic-file.js";
import type { CoverageReport, ExpandedSurfaceInventoryItem } from "./coverage.js";

export interface ProposeMatchersOptions {
  projectRoot: string;
  agentType: string;
  agentConfig: Record<string, unknown>;
  inventory: ExpandedSurfaceInventoryItem[];
  coverage: CoverageReport;
  existingSlugs: string[];
  signal?: AbortSignal;
  onProgress?: (progress: AgentProgress) => void;
  runTask?: typeof runSetupTask;
}

function extractArray(raw: string): unknown[] {
  const fenced = raw.match(/```(?:json)?\s*([\s\S]*?)```/i)?.[1];
  const text = (fenced ?? raw).trim();
  const parsed = JSON.parse(text.slice(text.indexOf("["), text.lastIndexOf("]") + 1));
  if (!Array.isArray(parsed)) throw new Error("Matcher proposal must be a JSON array");
  return parsed;
}

export async function proposeGeneratedMatchers(
  options: ProposeMatchersOptions,
): Promise<{ specs: DeclarativeMatcherSpec[]; plugins: DeclarativeMatcherPlugin[] }> {
  const uncovered = options.coverage.surfaces.filter((surface) => !surface.passed);
  if (uncovered.length === 0 && options.coverage.languageWarnings.length === 0) {
    return { specs: [], plugins: [] };
  }
  const prompt = `Design narrow, data-only deepsec coverage matchers for the repository. Read files only; do not execute code, use the network, read env files, or install packages.

Return ONLY a JSON array. Each item must have exactly: version:1, slug (kebab-case), description, noiseTier (precise|normal|noisy), filePatterns, optional requires {tech and/or sentinelFiles}, patterns [{source, optional flags i|m|im, label}], optional excludeFilePatterns, examples (each must match a pattern), and closesSurfaceIds.

Only close a surface when the matcher targets its concrete framework/registration primitive. Prefer anchored, framework-specific patterns. Never emit a broad catch-all. Existing slugs must not be reused: ${JSON.stringify(options.existingSlugs)}.

Inventory: ${JSON.stringify(options.inventory)}
Coverage gaps: ${JSON.stringify({ surfaces: uncovered, languages: options.coverage.languageWarnings })}`;
  const runTask = options.runTask ?? runSetupTask;
  let raw = await runTask({
    agentType: options.agentType,
    projectRoot: options.projectRoot,
    prompt,
    config: options.agentConfig,
    signal: options.signal,
    onProgress: options.onProgress,
  });
  try {
    const plugins = compileDeclarativeMatchers(extractArray(raw), {
      existingSlugs: options.existingSlugs,
    });
    return { specs: plugins.map((plugin) => plugin.declarativeSpec), plugins };
  } catch (error) {
    raw = await runTask({
      agentType: options.agentType,
      projectRoot: options.projectRoot,
      prompt: `${prompt}\n\nThe previous output failed validation: ${error instanceof Error ? error.message : String(error)}. Return a corrected JSON array only.`,
      config: options.agentConfig,
      signal: options.signal,
      onProgress: options.onProgress,
    });
    const plugins = compileDeclarativeMatchers(extractArray(raw), {
      existingSlugs: options.existingSlugs,
    });
    return { specs: plugins.map((plugin) => plugin.declarativeSpec), plugins };
  }
}

export function writeGeneratedMatchers(
  workspaceDir: string,
  specs: DeclarativeMatcherSpec[],
): string {
  const file = path.join(workspaceDir, "generated-matchers.ts");
  const content = `import { compileDeclarativeMatchers, type DeepsecPlugin } from "deepsec/config";\n\nconst specs = ${JSON.stringify(specs, null, 2)};\n\nexport const generatedMatchersPlugin: DeepsecPlugin = {\n  name: "deepsec-generated-matchers",\n  matchers: compileDeclarativeMatchers(specs),\n};\n`;
  atomicWriteFileSync(file, content);
  return file;
}

/** Read the specs from Deepsec's generated file so resumed setup only appends. */
export function readGeneratedMatchers(workspaceDir: string): DeclarativeMatcherPlugin[] {
  const file = path.join(workspaceDir, "generated-matchers.ts");
  if (!fs.existsSync(file)) return [];
  const source = fs.readFileSync(file, "utf8");
  const serialized = source.match(/const specs\s*=\s*(\[[\s\S]*?\]);\s*\n\s*export const/)?.[1];
  if (!serialized) return [];
  return compileDeclarativeMatchers(JSON.parse(serialized));
}

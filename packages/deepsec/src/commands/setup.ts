import path from "node:path";
import { findProject, getConfig, getConfigPath } from "@deepsec/core";
import { type ModelProfile, parseModelProfile, resolveModelProfile } from "../auth/model-picker.js";
import type { ModelRoute } from "../auth/model-route.js";
import { resolveProjectId } from "../resolve-project-id.js";
import { runSetupWorkflow, type SetupThrough } from "../setup/coordinator.js";
import type { SupportedPackageManager } from "../setup/install.js";
import { shouldUseHeadlessMode } from "../setup/interaction.js";
import { acquireSetupLock } from "../setup/lock.js";
import { type ModelRouteCliOptions, modelRouteFromCli } from "../setup/options.js";
import { deterministicVercelProjectName } from "../setup/project-name.js";
import {
  parseSetupOutputMode,
  type SetupOutputMode,
  SetupProtocolError,
  setSetupDocumentationWorkspace,
} from "../setup/protocol.js";
import { createSetupReporter, printSetupSummary } from "../setup/reporter.js";
import { readSetupState } from "../setup/state.js";
import { buildSetupStatus } from "../setup/status.js";

export interface SetupCommandOptions extends ModelRouteCliOptions {
  projectId?: string;
  root?: string;
  model?: string;
  modelProfile?: ModelProfile | string;
  thinkingLevel?: string;
  packageManager?: SupportedPackageManager;
  skipInstall?: boolean;
  headless?: boolean;
  nonInteractive?: boolean;
  yes?: boolean;
  vercelTeamId?: string;
  vercelProjectId?: string;
  vercelProjectName?: string;
  concurrency?: number;
  tui?: boolean;
  output?: SetupOutputMode | string;
  status?: boolean;
  through?: SetupThrough;
  maxCostUsd?: number;
  maxDurationMs?: number;
  maxDuration?: number;
}

export async function setupCommand(options: SetupCommandOptions): Promise<void> {
  setSetupDocumentationWorkspace(process.cwd());
  const headless = shouldUseHeadlessMode(options);
  const outputMode = parseSetupOutputMode(options.output);
  const projectId = resolveProjectId(options.projectId);
  const project = findProject(projectId);
  const configPath = getConfigPath();
  if (!configPath) throw new Error("Run deepsec setup from a workspace with deepsec.config.ts");
  const workspaceDir = path.dirname(configPath);
  setSetupDocumentationWorkspace(workspaceDir);
  const projectRoot = options.root
    ? path.resolve(options.root)
    : project
      ? path.resolve(workspaceDir, project.root)
      : undefined;
  if (!projectRoot) throw new Error(`Project ${projectId} is missing from deepsec.config.ts`);

  if (options.status) {
    const status = buildSetupStatus({
      workspaceDir,
      projectId,
      state: readSetupState(projectId),
    });
    console.log(JSON.stringify(status, null, outputMode === "jsonl" ? undefined : 2));
    return;
  }

  const routeWasProvided = Boolean(
    options.modelAuth ||
      options.aiProvider ||
      options.aiApiKeyEnv ||
      options.aiBaseUrl ||
      options.aiCredentialHeader,
  );
  const configuredRoute = getConfig()?.ai as ModelRoute | undefined;
  const route = routeWasProvided ? modelRouteFromCli(options) : configuredRoute;
  let agent = options.agent;
  let model = options.model;
  let thinkingLevel = options.thinkingLevel;
  const profile = parseModelProfile(options.modelProfile);
  if (
    headless &&
    !model &&
    !profile &&
    !options.yes &&
    !getConfig()?.defaultModel &&
    !readSetupState(projectId)?.agent.model
  ) {
    throw new SetupProtocolError({
      code: "MODEL_SELECTION_REQUIRED",
      message: "Choose --model-profile best, value, or budget before the first headless setup.",
      missingInputs: ["model.profile"],
      choices: [
        { value: "best", label: "Best benchmark score", recommended: true },
        { value: "value", label: "Best score within 2.5× relative benchmark cost" },
        { value: "budget", label: "Lowest-cost recommended combination" },
      ],
    });
  }
  if (!model && (profile || (headless && options.yes && !getConfig()?.defaultModel))) {
    const choice = await resolveModelProfile({
      profile: profile ?? "best",
      route: route ?? { mode: "gateway", provider: "vercel" },
      agent,
    });
    agent = choice.agent;
    model = choice.model;
    thinkingLevel = choice.thinkingLevel;
  }
  const abortController = new AbortController();
  const releaseSetupLock = acquireSetupLock(workspaceDir);
  let reporter: Awaited<ReturnType<typeof createSetupReporter>> | undefined;
  try {
    reporter = await createSetupReporter({
      workspaceDir,
      projectId,
      noTui: options.tui === false,
      onCancel: () => abortController.abort(),
      outputMode,
    });
    const result = await runSetupWorkflow({
      workspaceDir,
      projectId,
      projectRoot,
      agent,
      model,
      thinkingLevel,
      modelRoute: route,
      packageManager: options.packageManager,
      skipInstall: options.skipInstall,
      nonInteractive: headless,
      teamId: options.vercelTeamId,
      vercelProjectId: options.vercelProjectId,
      allowProjectCreate: options.yes,
      vercelProjectName:
        options.vercelProjectName ?? deterministicVercelProjectName(projectId, projectRoot),
      concurrency: options.concurrency,
      through: options.through,
      maxCostUsd: options.maxCostUsd,
      maxDurationMs: options.maxDurationMs ?? options.maxDuration,
      signal: abortController.signal,
      reporter,
    });
    await reporter.close("success");
    printSetupSummary(result, { workspaceDir, projectId, logPath: reporter.logPath, outputMode });
  } catch (error) {
    await reporter?.close(abortController.signal.aborted ? "cancelled" : "error");
    if (reporter?.logPath && outputMode === "human") {
      console.error(`Full setup log: ${reporter.logPath}`);
    }
    throw error;
  } finally {
    releaseSetupLock();
  }
}

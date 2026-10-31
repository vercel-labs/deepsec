import fs from "node:fs";
import path from "node:path";
import type { ModelProfile } from "../auth/model-picker.js";
import { resolveModelProfile } from "../auth/model-picker.js";
import type { ModelRoute } from "../auth/model-route.js";
import {
  type RunVercelCli,
  readWorkspaceLink,
  runPinnedVercelCli,
  vercelAuthRecoveryActions,
} from "../auth/vercel-link.js";
import { loadEnvFile } from "../env-file.js";
import { listRepositoryFiles, setupRepositoryIgnoreGlobs } from "./fingerprint.js";
import type { SupportedPackageManager } from "./install.js";
import {
  type SetupAction,
  type SetupDocumentation,
  setSetupDocumentationWorkspace,
  setupDocumentation,
} from "./protocol.js";

export interface SetupPlan {
  type: "plan";
  ready: boolean;
  repository: { id: string; root: string; files: number };
  workspace: { path: string; exists: boolean; resumable: boolean };
  install: { required: boolean; packageManager: SupportedPackageManager };
  vercel: {
    action: "reuse-link" | "use-token-triple" | "discover-cli";
    link?: { teamId: string; projectId: string };
    credentialSources: string[];
    deterministicProjectName: string;
  };
  model?: {
    profile?: ModelProfile;
    agent: string;
    model: string;
    thinkingLevel?: string;
    score?: number;
    relativePrice?: number;
    benchmarkData?: "live" | "cached";
  };
  phases: string[];
  missingInputs: string[];
  suggestedArgs: string[];
  actions: SetupAction[];
  documentation?: SetupDocumentation;
}

function plannedPackageManager(
  projectRoot: string,
  explicit?: SupportedPackageManager,
): SupportedPackageManager {
  if (explicit) return explicit;
  if (fs.existsSync(path.join(projectRoot, "package-lock.json"))) return "npm";
  return "pnpm";
}

export async function buildSetupPlan(options: {
  workspaceDir: string;
  projectRoot: string;
  projectId: string;
  packageManager?: SupportedPackageManager;
  modelRoute?: ModelRoute;
  modelProfile?: ModelProfile;
  model?: string;
  agent?: string;
  thinkingLevel?: string;
  yes?: boolean;
  teamId?: string;
  vercelProjectId?: string;
  deterministicProjectName: string;
  env?: NodeJS.ProcessEnv;
  runCli?: RunVercelCli;
}): Promise<SetupPlan> {
  const workspaceDir = path.resolve(options.workspaceDir);
  setSetupDocumentationWorkspace(workspaceDir);
  const projectRoot = path.resolve(options.projectRoot);
  const env = { ...(options.env ?? process.env) };
  await loadEnvFile(path.join(workspaceDir, ".env.local"), env);
  const link = await readWorkspaceLink(workspaceDir);
  const tokenTriple = Boolean(
    env.VERCEL_TOKEN &&
      (options.teamId ?? env.VERCEL_TEAM_ID) &&
      (options.vercelProjectId ?? env.VERCEL_PROJECT_ID),
  );
  const linkCredential = Boolean(link && (env.VERCEL_OIDC_TOKEN || env.VERCEL_TOKEN));
  let cliAuthenticated = false;
  if (!linkCredential && !tokenTriple) {
    try {
      cliAuthenticated =
        (await (options.runCli ?? runPinnedVercelCli)(["whoami"], projectRoot)).exitCode === 0;
    } catch {}
  }
  const missingInputs: string[] = [];
  const suggestedArgs: string[] = [];
  const actions: SetupAction[] = [];
  if (!linkCredential && !tokenTriple && !cliAuthenticated) {
    missingInputs.push("vercel.authentication");
    actions.push(...vercelAuthRecoveryActions(workspaceDir, link !== null));
  } else if (!link && !tokenTriple && !options.vercelProjectId && !options.yes) {
    missingInputs.push("vercel.projectCreationApproval");
    suggestedArgs.push("--yes");
  }

  let model: SetupPlan["model"];
  if (options.model) {
    model = {
      agent: options.agent ?? "codex",
      model: options.model,
      thinkingLevel: options.thinkingLevel,
    };
  } else if (options.modelProfile || options.yes) {
    const profile = options.modelProfile ?? "best";
    const selected = await resolveModelProfile({
      profile,
      route: options.modelRoute ?? { mode: "gateway", provider: "vercel" },
      agent: options.agent,
    });
    model = {
      profile,
      agent: selected.agent,
      model: selected.model,
      thinkingLevel: selected.thinkingLevel,
      score: selected.score,
      relativePrice: selected.relativePrice,
      benchmarkData: selected.live ? "live" : "cached",
    };
  } else {
    missingInputs.push("model.profile");
    suggestedArgs.push("--model-profile", "best");
  }

  const workspaceExists = fs.existsSync(workspaceDir);
  const repositoryFiles = listRepositoryFiles(
    projectRoot,
    setupRepositoryIgnoreGlobs(projectRoot, workspaceDir),
  );
  const documentation = setupDocumentation();
  return {
    type: "plan",
    ready: missingInputs.length === 0,
    repository: { id: options.projectId, root: projectRoot, files: repositoryFiles.length },
    workspace: {
      path: workspaceDir,
      exists: workspaceExists,
      resumable:
        workspaceExists &&
        fs.existsSync(path.join(workspaceDir, "deepsec.config.ts")) &&
        fs.existsSync(path.join(workspaceDir, "data", options.projectId, "project.json")),
    },
    install: {
      required: !fs.existsSync(path.join(workspaceDir, "node_modules", "deepsec")),
      packageManager: plannedPackageManager(projectRoot, options.packageManager),
    },
    vercel: {
      action: linkCredential ? "reuse-link" : tokenTriple ? "use-token-triple" : "discover-cli",
      ...(link ? { link: { teamId: link.orgId, projectId: link.projectId } } : {}),
      credentialSources: [
        ...(env.VERCEL_OIDC_TOKEN ? ["oidc"] : []),
        ...(env.VERCEL_TOKEN ? ["access-token"] : []),
        ...(cliAuthenticated ? ["vercel-cli-authenticated"] : ["vercel-cli"]),
      ],
      deterministicProjectName: options.deterministicProjectName,
    },
    model,
    phases: [
      "workspace",
      "install",
      "vercel-and-model-access",
      "threat-model",
      "baseline-scan",
      "coverage",
      "generated-matchers",
      "final-scan",
      "ai-investigation",
    ],
    missingInputs,
    suggestedArgs,
    actions,
    ...(documentation ? { documentation } : {}),
  };
}

import { join } from "node:path";
import { getVercelOidcToken } from "@vercel/oidc";
import { updateEnvFile } from "../env-file.js";
import { assertSandboxCredential } from "../preflight.js";
import {
  applyResolvedModelRoute,
  type ModelRoute,
  type ModelRouteVerifier,
  type ResolvedModelRoute,
  resolveModelRoute,
  verifyModelRouteWithFetch,
} from "./model-route.js";
import {
  type EnsureVercelLinkOptions,
  ensureVercelLink,
  type PlatformLinkResult,
} from "./vercel-link.js";

export interface ConnectionVerificationCheckpoint {
  /** Absent for local-subscription routes, which never link a project. */
  project?: { teamId: string; projectId: string };
  route: ModelRoute;
  agentTypes: string[];
  modelVerifiedAt: string;
  /** Legacy fields retained only when reading setup state created before 2.3. */
  sandboxVerifiedAt?: string;
  sandboxSmokeTestId?: string;
  sandboxSmokeTestStopped?: boolean;
}

export interface LoginResult {
  /** Absent for local-subscription routes, which never link a project. */
  platformAuth?: {
    method: "existing-link" | "vercel-cli" | "access-token-triple";
  };
  project?: { teamId: string; projectId: string };
  modelAuth: ModelRoute;
  agentTypes: string[];
  modelRouteVerified: boolean;
  sandboxReady: boolean;
  verification: ConnectionVerificationCheckpoint;
}

export interface EnsureConnectedWorkspaceDependencies {
  ensureLink?: (options: EnsureVercelLinkOptions) => Promise<PlatformLinkResult>;
  resolveRoute?: typeof resolveModelRoute;
  verifyModelRoute?: ModelRouteVerifier;
  refreshOidcToken?: typeof getVercelOidcToken;
  now?: () => Date;
}

export interface EnsureConnectedWorkspaceOptions {
  workspaceDir: string;
  interactive: boolean;
  modelRoute: ModelRoute;
  agentTypes: string[];
  env?: NodeJS.ProcessEnv;
  teamId?: string;
  projectId?: string;
  allowCreate?: boolean;
  projectName?: string;
  previous?: ConnectionVerificationCheckpoint;
  verificationTtlMs?: number;
  runCli?: EnsureVercelLinkOptions["runCli"];
  onLog?: (message: string) => void;
  dependencies?: EnsureConnectedWorkspaceDependencies;
}

function sameRoute(left: ModelRoute, right: ModelRoute): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function fresh(at: string, now: Date, ttl: number): boolean {
  const timestamp = Date.parse(at);
  return (
    Number.isFinite(timestamp) && now.getTime() - timestamp >= 0 && now.getTime() - timestamp < ttl
  );
}

function canReuseModel(
  previous: ConnectionVerificationCheckpoint | undefined,
  platform: PlatformLinkResult,
  route: ModelRoute,
  agents: string[],
  now: Date,
  ttl: number,
): boolean {
  return Boolean(
    previous &&
      previous.project?.teamId === platform.project.teamId &&
      previous.project?.projectId === platform.project.projectId &&
      sameRoute(previous.route, route) &&
      JSON.stringify(previous.agentTypes) === JSON.stringify(agents) &&
      fresh(previous.modelVerifiedAt, now, ttl),
  );
}

/** Reconcile the exact workspace link and explicit model route. */
export async function ensureConnectedWorkspace(
  options: EnsureConnectedWorkspaceOptions,
): Promise<LoginResult> {
  if (options.agentTypes.length === 0) throw new Error("At least one model agent is required");
  const env = options.env ?? process.env;
  const deps = options.dependencies ?? {};
  const now = (deps.now ?? (() => new Date()))();
  const ttl = options.verificationTtlMs ?? 24 * 60 * 60 * 1000;

  if (options.modelRoute.mode === "local") {
    // Local subscriptions delegate model auth to the machine-wide
    // claude/codex/pi logins, and nothing else in host-side setup needs the
    // platform. Linking anyway would prompt for the Vercel login the user
    // just declined and leave a VERCEL_OIDC_TOKEN in .env.local that every
    // later run expands into ANTHROPIC_BASE_URL / ANTHROPIC_AUTH_TOKEN,
    // routing past the login they chose. Sandbox commands do need the
    // platform and assert their own credential when they run.
    const verification: ConnectionVerificationCheckpoint = {
      route: options.modelRoute,
      agentTypes: [...options.agentTypes],
      modelVerifiedAt: now.toISOString(),
    };
    return {
      modelAuth: options.modelRoute,
      agentTypes: [...options.agentTypes],
      modelRouteVerified: false,
      sandboxReady: false,
      verification,
    };
  }

  const platform = await (deps.ensureLink ?? ensureVercelLink)({
    workspaceDir: options.workspaceDir,
    interactive: options.interactive,
    env,
    teamId: options.teamId,
    projectId: options.projectId,
    allowCreate: options.allowCreate,
    projectName: options.projectName,
    runCli: options.runCli,
    onLog: options.onLog,
  });

  if (options.interactive && env.VERCEL_OIDC_TOKEN) {
    const refreshed = await (deps.refreshOidcToken ?? getVercelOidcToken)({
      expirationBufferMs: 60 * 60 * 1000,
      team: platform.project.teamId,
      project: platform.project.projectId,
    });
    if (refreshed !== env.VERCEL_OIDC_TOKEN) {
      env.VERCEL_OIDC_TOKEN = refreshed;
      await updateEnvFile(join(options.workspaceDir, ".env.local"), {
        VERCEL_OIDC_TOKEN: refreshed,
      });
    }
  }

  // Link success is not enough: the credential must still be available now.
  assertSandboxCredential({ env });

  const resolvedRoutes: ResolvedModelRoute[] = [];
  for (const agentType of options.agentTypes) {
    const resolved = await (deps.resolveRoute ?? resolveModelRoute)(options.modelRoute, {
      agentType,
      env,
      vercelTeam: platform.project.teamId,
      vercelProject: platform.project.projectId,
    });
    resolvedRoutes.push(resolved);
    applyResolvedModelRoute(resolved, env);
  }

  const reuseModel = canReuseModel(
    options.previous,
    platform,
    resolvedRoutes[0].route,
    options.agentTypes,
    now,
    ttl,
  );
  if (!reuseModel) {
    for (const resolved of resolvedRoutes) {
      await (deps.verifyModelRoute ?? verifyModelRouteWithFetch)(resolved);
    }
  }

  const modelVerifiedAt = reuseModel ? options.previous!.modelVerifiedAt : now.toISOString();
  const normalizedRoute = resolvedRoutes[0].route;
  const verification: ConnectionVerificationCheckpoint = {
    project: platform.project,
    route: normalizedRoute,
    agentTypes: [...options.agentTypes],
    modelVerifiedAt,
  };

  return {
    platformAuth: { method: platform.method },
    project: platform.project,
    modelAuth: normalizedRoute,
    agentTypes: [...options.agentTypes],
    modelRouteVerified: true,
    sandboxReady: true,
    verification,
  };
}

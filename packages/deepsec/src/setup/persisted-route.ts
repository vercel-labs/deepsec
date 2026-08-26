import type { ModelRoute } from "../auth/model-route.js";
import { readSetupState } from "./state.js";
import { persistWorkspaceConfigRoute, readWorkspaceConfigRoute } from "./workspace-config.js";

/**
 * Record the route a run starts with before install, the first interruptible
 * phase. Setup writes its own checkpoint only after login succeeds, and
 * neither the route prompt nor a one-off `--model-auth` flag is repeated on
 * resume, so an interrupt in between would otherwise resume onto the gateway
 * default. A resumed run carries no route of its own and leaves the recorded
 * one alone.
 */
export function recordInitialModelRoute(workspaceDir: string, route?: ModelRoute): void {
  if (!route) return;
  persistWorkspaceConfigRoute(workspaceDir, route);
}

/**
 * Route a resumed run must reuse. The login checkpoint is authoritative once
 * setup got that far; before it, the only record is the route line the first
 * run wrote into the generated config. Init prompts for a route on a first run
 * only, so a resume with neither would silently fall back to the gateway.
 */
export function persistedModelRoute(
  workspaceDir: string,
  projectId: string,
): ModelRoute | undefined {
  return checkpointRoute(workspaceDir, projectId) ?? readWorkspaceConfigRoute(workspaceDir);
}

/** Setup state paths resolve against the data root, which is relative to cwd. */
function checkpointRoute(workspaceDir: string, projectId: string): ModelRoute | undefined {
  const originalCwd = process.cwd();
  try {
    process.chdir(workspaceDir);
    const connection = readSetupState(projectId)?.connection as { route?: ModelRoute } | undefined;
    return connection?.route;
  } catch {
    return undefined;
  } finally {
    process.chdir(originalCwd);
  }
}

import type { ModelAuthMode, ResolvedModelRoute } from "../auth/model-route.js";
import { applySelectedModelRoute } from "../preflight.js";
import { modelRouteFromCli } from "../setup/options.js";
import { extractFlag } from "./args.js";

/**
 * One-run route flags read from the `sandbox` / `sandbox-all` passthrough
 * args. Same vocabulary as `process` / `revalidate --model-auth`.
 */
interface SandboxModelRouteFlags {
  modelAuth?: ModelAuthMode;
  aiProvider?: string;
  aiApiKeyEnv?: string;
  aiBaseUrl?: string;
  aiCredentialHeader?: string;
}

/**
 * The local-subscription route has no brokered credential. Sandbox workers
 * have no machine-wide Codex/Claude/Pi login, so the override cannot be
 * honored remotely: reject it on the orchestrator instead of letting the
 * worker fail mid-batch after provisioning.
 */
const SANDBOX_LOCAL_ROUTE_ERROR =
  "--model-auth local is not supported with deepsec sandbox: Vercel Sandbox workers have no " +
  "machine-wide Codex, Claude, or Pi login, so every sandbox run uses a credential brokered " +
  "from the orchestrator. Run process or revalidate locally for a subscription route, or pass " +
  "--model-auth gateway (or --model-auth direct/custom with a provider credential) here.";

/** Extract `--model-auth` and the provider flags that shape that route. */
export function extractSandboxModelRouteFlags(args: string[]): SandboxModelRouteFlags {
  const modelAuth = extractFlag(args, "--model-auth") as ModelAuthMode | undefined;
  if (modelAuth === undefined && args.some((a) => a === "--model-auth" || a === "--model-auth=")) {
    throw new Error("sandbox --model-auth requires a value (gateway, direct, custom, or local)");
  }
  return {
    modelAuth,
    aiProvider: extractFlag(args, "--ai-provider"),
    aiApiKeyEnv: extractFlag(args, "--ai-api-key-env"),
    aiBaseUrl: extractFlag(args, "--ai-base-url"),
    aiCredentialHeader: extractFlag(args, "--ai-credential-header"),
  };
}

/**
 * Resolve a one-run model-route override for a sandboxed run and return the
 * host-side broker the orchestrator must install in the worker firewall.
 *
 * Returns undefined when no override was passed, so the saved route keeps
 * driving the sandbox exactly as before. Local subscriptions are rejected:
 * they can never be brokered into a worker.
 */
export async function resolveSandboxModelRoute(
  flags: SandboxModelRouteFlags,
  agentType: string,
  env: NodeJS.ProcessEnv = process.env,
): Promise<ResolvedModelRoute | undefined> {
  if (!flags.modelAuth) return undefined;
  const route = modelRouteFromCli({
    modelAuth: flags.modelAuth,
    aiProvider: flags.aiProvider,
    aiApiKeyEnv: flags.aiApiKeyEnv,
    aiBaseUrl: flags.aiBaseUrl,
    aiCredentialHeader: flags.aiCredentialHeader,
    agent: agentType,
  });
  if (route.mode === "local") throw new Error(SANDBOX_LOCAL_ROUTE_ERROR);
  // Resolve and apply on the host: the resolved environment (base URLs,
  // expanded credentials) is read by buildSandboxEnv, and the broker becomes
  // the worker firewall transform. The real credential never enters the VM.
  return applySelectedModelRoute(route, agentType, env);
}

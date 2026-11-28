import { type AgentRuntimeOpts, buildAgentConfig } from "./agent-config.js";
import type { ModelRoute } from "./auth/model-route.js";
import { applyCommandModelRoute, applyConfiguredModelRoute } from "./preflight.js";
import { modelRouteFromCli } from "./setup/options.js";

/**
 * Resolve the model route and agent config for a run command (`process`,
 * `revalidate`).
 *
 * Without `--model-auth` this is the normal behavior: the saved route is
 * rehydrated when it is compatible and provides a credential. An explicit
 * `--model-auth` overrides the saved route for this one run — the escape
 * hatch from a persisted local-subscription route, using the same route
 * vocabulary as `init`/`setup`.
 */
export async function resolveRunAgentConfig(
  opts: AgentRuntimeOpts,
): Promise<{ agentConfig: Record<string, unknown>; explicitRoute?: ModelRoute }> {
  let route: ModelRoute | undefined;
  if (opts.modelAuth) {
    // Pass the resolved agent type as `agent`: a one-run direct/custom route
    // may omit --ai-provider, and the provider then defaults from the harness
    // the command actually runs (including defaultAgent from deepsec.config.ts).
    route = await applyCommandModelRoute(
      modelRouteFromCli({
        modelAuth: opts.modelAuth,
        aiProvider: opts.aiProvider,
        aiApiKeyEnv: opts.aiApiKeyEnv,
        aiBaseUrl: opts.aiBaseUrl,
        aiCredentialHeader: opts.aiCredentialHeader,
        agent: opts.agentType,
      }),
      opts.agentType,
    );
  } else if (!opts.aiApiKeyEnv && !opts.aiBaseUrl) {
    route = (await applyConfiguredModelRoute(opts.agentType))?.route;
  }
  return {
    agentConfig: buildAgentConfig({ ...opts, modelRoute: route }),
    explicitRoute: opts.modelAuth ? route : undefined,
  };
}

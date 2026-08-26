import { describe, expect, it, vi } from "vitest";
import { ensureConnectedWorkspace } from "../auth/ensure-connected-workspace.js";
import type { ResolvedModelRoute } from "../auth/model-route.js";

const route = { mode: "direct", provider: "openai", apiKeyEnv: "OPENAI_API_KEY" } as const;

function resolved(): ResolvedModelRoute {
  return {
    route,
    credentialEnv: "OPENAI_API_KEY",
    credential: "secret",
    environment: { OPENAI_API_KEY: "secret" },
    broker: {
      host: "api.openai.com",
      placeholderEnv: "OPENAI_API_KEY",
      header: { name: "authorization", value: "Bearer secret" },
    },
  };
}

describe("ensureConnectedWorkspace", () => {
  it("verifies model access and returns an auditable linked checkpoint", async () => {
    const verifyModelRoute = vi.fn(async () => undefined);
    const result = await ensureConnectedWorkspace({
      workspaceDir: "/workspace",
      interactive: false,
      modelRoute: route,
      agentTypes: ["codex"],
      env: { VERCEL_TOKEN: "v", VERCEL_TEAM_ID: "team", VERCEL_PROJECT_ID: "project" },
      dependencies: {
        ensureLink: async () => ({
          method: "access-token-triple",
          project: { teamId: "team", projectId: "project" },
          link: { orgId: "team", projectId: "project" },
        }),
        resolveRoute: async () => resolved(),
        verifyModelRoute,
        now: () => new Date("2026-01-01T00:00:00Z"),
      },
    });
    expect(result.modelRouteVerified).toBe(true);
    expect(result.sandboxReady).toBe(true);
    expect(verifyModelRoute).toHaveBeenCalledOnce();
  });

  it("short-circuits fresh matching verification while still resolving credentials", async () => {
    const verifyModelRoute = vi.fn(async () => undefined);
    const resolveRoute = vi.fn(async () => resolved());
    const previous = {
      project: { teamId: "team", projectId: "project" },
      route,
      agentTypes: ["codex"],
      modelVerifiedAt: "2026-01-01T00:00:00Z",
    };
    const result = await ensureConnectedWorkspace({
      workspaceDir: "/workspace",
      interactive: false,
      modelRoute: route,
      agentTypes: ["codex"],
      env: { VERCEL_TOKEN: "v", VERCEL_TEAM_ID: "team", VERCEL_PROJECT_ID: "project" },
      previous,
      dependencies: {
        ensureLink: async () => ({
          method: "existing-link",
          project: { teamId: "team", projectId: "project" },
          link: { orgId: "team", projectId: "project" },
        }),
        resolveRoute,
        verifyModelRoute,
        now: () => new Date("2026-01-01T01:00:00Z"),
      },
    });
    expect(resolveRoute).toHaveBeenCalledOnce();
    expect(verifyModelRoute).not.toHaveBeenCalled();
    expect(result.sandboxReady).toBe(true);
  });

  it("skips the platform link, credential resolution and verification for a local route", async () => {
    const resolveRoute = vi.fn(async () => resolved());
    const verifyModelRoute = vi.fn(async () => undefined);
    const ensureLink = vi.fn(async () => ({
      method: "access-token-triple" as const,
      project: { teamId: "team", projectId: "project" },
      link: { orgId: "team", projectId: "project" },
    }));
    const localRoute = { mode: "local", provider: "local" } as const;
    const env = { VERCEL_TOKEN: "v", VERCEL_TEAM_ID: "team", VERCEL_PROJECT_ID: "project" };
    const result = await ensureConnectedWorkspace({
      workspaceDir: "/workspace",
      interactive: false,
      modelRoute: localRoute,
      agentTypes: ["claude-agent-sdk"],
      env,
      dependencies: {
        ensureLink,
        resolveRoute,
        verifyModelRoute,
        now: () => new Date("2026-01-01T00:00:00Z"),
      },
    });
    expect(ensureLink).not.toHaveBeenCalled();
    expect(result.project).toBeUndefined();
    expect(resolveRoute).not.toHaveBeenCalled();
    expect(verifyModelRoute).not.toHaveBeenCalled();
    expect(result.modelAuth).toEqual(localRoute);
    expect(result.modelRouteVerified).toBe(false);
    expect(result.verification.route).toEqual(localRoute);
    // No model credential env vars were injected.
    expect(env).toEqual({
      VERCEL_TOKEN: "v",
      VERCEL_TEAM_ID: "team",
      VERCEL_PROJECT_ID: "project",
    });
  });
});

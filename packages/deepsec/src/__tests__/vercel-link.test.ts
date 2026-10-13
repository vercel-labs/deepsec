import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { ensureVercelLink, readWorkspaceLink } from "../auth/vercel-link.js";
import { SetupProtocolError } from "../setup/protocol.js";

describe("Vercel project link", () => {
  it("writes an exact-workspace link for the non-interactive triple", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "deepsec-link-"));
    const env = {
      VERCEL_TOKEN: "secret",
      VERCEL_TEAM_ID: "team_1",
      VERCEL_PROJECT_ID: "prj_1",
    };
    const result = await ensureVercelLink({ workspaceDir: workspace, interactive: false, env });
    expect(result.method).toBe("access-token-triple");
    expect(await readWorkspaceLink(workspace)).toEqual({ orgId: "team_1", projectId: "prj_1" });
  });

  it("reuses an exact workspace link and OIDC credential headlessly", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "deepsec-headless-oidc-"));
    await mkdir(join(workspace, ".vercel"));
    await writeFile(
      join(workspace, ".vercel", "project.json"),
      '{"orgId":"team_existing","projectId":"project_existing"}',
    );
    await writeFile(join(workspace, ".env.local"), "VERCEL_OIDC_TOKEN=oidc-existing\n");
    const env: NodeJS.ProcessEnv = {};
    const runCli = vi.fn();

    const result = await ensureVercelLink({
      workspaceDir: workspace,
      interactive: false,
      env,
      runCli,
    });

    expect(result.method).toBe("existing-link");
    expect(result.project).toEqual({ teamId: "team_existing", projectId: "project_existing" });
    expect(env.VERCEL_OIDC_TOKEN).toBe("oidc-existing");
    expect(runCli).not.toHaveBeenCalled();
  });

  it("combines an exact workspace link with a headless access token", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "deepsec-headless-token-"));
    await mkdir(join(workspace, ".vercel"));
    await writeFile(
      join(workspace, ".vercel", "project.json"),
      '{"orgId":"team_existing","projectId":"project_existing"}',
    );
    const env: NodeJS.ProcessEnv = { VERCEL_TOKEN: "secret" };

    const result = await ensureVercelLink({ workspaceDir: workspace, interactive: false, env });

    expect(result.method).toBe("access-token-triple");
    expect(env.VERCEL_TEAM_ID).toBe("team_existing");
    expect(env.VERCEL_PROJECT_ID).toBe("project_existing");
  });

  it("returns structured login instructions when headless Vercel auth is missing", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "deepsec-headless-login-"));
    const runCli = vi.fn(async () => ({ exitCode: 1, stdout: "", stderr: "not logged in" }));

    const error = await ensureVercelLink({
      workspaceDir: workspace,
      interactive: false,
      env: {},
      runCli,
    }).catch((value) => value);

    expect(error).toBeInstanceOf(SetupProtocolError);
    expect(error).toMatchObject({
      code: "VERCEL_AUTH_REQUIRED",
      missingInputs: ["vercel.authentication"],
    });
    expect(error.actions[0].commands).toContain("npx vercel login");
    expect(error.actions[1]).toMatchObject({
      id: "vercel-link-workspace",
      commands: [expect.stringContaining(workspace), "npx vercel link"],
    });
    expect(error.actions[2]).toMatchObject({
      id: "vercel-link-known-project",
      commands: [
        expect.stringContaining(workspace),
        "npx vercel link --yes --team <team-slug> --project <project-name>",
      ],
    });
  });

  it("does not ask the agent to relink an existing workspace after login", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "deepsec-headless-login-linked-"));
    await mkdir(join(workspace, ".vercel"));
    await writeFile(
      join(workspace, ".vercel", "project.json"),
      '{"orgId":"team_existing","projectId":"project_existing"}',
    );
    const runCli = vi.fn(async () => ({ exitCode: 1, stdout: "", stderr: "not logged in" }));

    const error = await ensureVercelLink({
      workspaceDir: workspace,
      interactive: false,
      env: {},
      runCli,
    }).catch((value) => value);

    expect(error.actions.map((action: { id: string }) => action.id)).toEqual([
      "vercel-login",
      "access-token",
    ]);
  });

  it("creates and links a deterministic project through an authenticated headless CLI", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "deepsec-headless-create-"));
    let projectCreated = false;
    const runCli = vi.fn(async (args: string[]) => {
      if (args[0] === "whoami") return { exitCode: 0, stdout: "user", stderr: "" };
      if (args[0] === "teams") {
        return {
          exitCode: 0,
          stdout: JSON.stringify({
            teams: [{ id: "team_1", slug: "acme", name: "Acme", current: true }],
          }),
          stderr: "",
        };
      }
      if (args[0] === "project" && args[1] === "list") {
        return {
          exitCode: 0,
          stdout: JSON.stringify({
            projects: projectCreated ? [{ id: "prj_1", name: "deepsec-app-abcd1234" }] : [],
          }),
          stderr: "",
        };
      }
      if (args[0] === "project" && args[1] === "add") {
        projectCreated = true;
        return { exitCode: 0, stdout: "created", stderr: "" };
      }
      if (args[0] === "link") {
        await mkdir(join(workspace, ".vercel"), { recursive: true });
        await writeFile(
          join(workspace, ".vercel", "project.json"),
          '{"orgId":"team_1","projectId":"prj_1","projectName":"deepsec-app-abcd1234"}',
        );
        return { exitCode: 0, stdout: "linked", stderr: "" };
      }
      if (args[0] === "env" && args[1] === "pull") {
        await writeFile(args[2], "VERCEL_OIDC_TOKEN=oidc-created\n");
        return { exitCode: 0, stdout: "", stderr: "" };
      }
      throw new Error(`unexpected ${args.join(" ")}`);
    });
    const env: NodeJS.ProcessEnv = {};

    const result = await ensureVercelLink({
      workspaceDir: workspace,
      interactive: false,
      env,
      runCli,
      allowCreate: true,
      projectName: "deepsec-app-abcd1234",
    });

    expect(result.project).toEqual({ teamId: "team_1", projectId: "prj_1" });
    expect(env.VERCEL_OIDC_TOKEN).toBe("oidc-created");
    expect(
      runCli.mock.calls.filter(([args]) => args[0] === "project" && args[1] === "add"),
    ).toHaveLength(1);
  });

  it("returns structured team choices when headless scope is ambiguous", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "deepsec-headless-team-"));
    const runCli = vi.fn(async (args: string[]) => {
      if (args[0] === "whoami") return { exitCode: 0, stdout: "user", stderr: "" };
      return {
        exitCode: 0,
        stdout: JSON.stringify({
          teams: [
            { id: "team_1", slug: "one", name: "One", current: true },
            { id: "team_2", slug: "two", name: "Two" },
          ],
        }),
        stderr: "",
      };
    });

    const error = await ensureVercelLink({
      workspaceDir: workspace,
      interactive: false,
      env: {},
      runCli,
      allowCreate: true,
      projectName: "deepsec-app",
    }).catch((value) => value);

    expect(error).toMatchObject({ code: "VERCEL_SCOPE_REQUIRED" });
    expect(error.choices).toHaveLength(2);
    expect(error.choices[0]).toMatchObject({ value: "team_1", recommended: true });
    expect(error.actions[0].resumeArgs).toEqual(["--vercel-team-id", "<choice>"]);
  });

  it("ignores an ancestor link and confines CLI calls to the workspace", async () => {
    const parent = await mkdtemp(join(tmpdir(), "deepsec-parent-link-"));
    const workspace = join(parent, "nested", ".deepsec");
    await mkdir(join(parent, ".vercel"), { recursive: true });
    await mkdir(workspace, { recursive: true });
    await writeFile(
      join(parent, ".vercel", "project.json"),
      '{"orgId":"wrong","projectId":"wrong"}',
    );
    const runCli = vi.fn(async (args: string[], cwd: string) => {
      expect(cwd).toBe(workspace);
      if (args[0] === "whoami") return { exitCode: 0, stdout: "user", stderr: "" };
      if (args[0] === "link") {
        await mkdir(join(workspace, ".vercel"), { recursive: true });
        await writeFile(
          join(workspace, ".vercel", "project.json"),
          '{"orgId":"team","projectId":"project"}',
        );
        await writeFile(join(workspace, ".env.local"), "KEEP=unchanged\nVERCEL_OIDC_TOKEN=oidc\n");
        return { exitCode: 0, stdout: "linked", stderr: "" };
      }
      throw new Error(`unexpected ${args.join(" ")}`);
    });
    const env: NodeJS.ProcessEnv = {};
    const result = await ensureVercelLink({
      workspaceDir: workspace,
      interactive: true,
      runCli,
      env,
    });
    expect(result.method).toBe("vercel-cli");
    expect(env.VERCEL_OIDC_TOKEN).toBe("oidc");
    expect(runCli.mock.calls.map(([args]) => args[0])).toEqual(["whoami", "link"]);
  });

  it("pulls only OIDC through a temporary file and preserves .env.local", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "deepsec-existing-link-"));
    await mkdir(join(workspace, ".vercel"));
    await writeFile(
      join(workspace, ".vercel", "project.json"),
      '{"orgId":"team","projectId":"project"}',
    );
    await writeFile(join(workspace, ".env.local"), "KEEP = exact # comment\n");
    const runCli = vi.fn(async (args: string[]) => {
      expect(args.slice(0, 2)).toEqual(["env", "pull"]);
      const output = args[2];
      await mkdir(dirname(output), { recursive: true });
      await writeFile(output, "SECRET_PROJECT_ENV=do-not-copy\nVERCEL_OIDC_TOKEN=oidc-new\n");
      return { exitCode: 0, stdout: "", stderr: "" };
    });
    const env: NodeJS.ProcessEnv = {};
    await ensureVercelLink({ workspaceDir: workspace, interactive: true, runCli, env });
    const contents = await readFile(join(workspace, ".env.local"), "utf8");
    expect(contents).toContain("KEEP = exact # comment");
    expect(contents).toContain("VERCEL_OIDC_TOKEN=oidc-new");
    expect(contents).not.toContain("SECRET_PROJECT_ENV");
  });
});

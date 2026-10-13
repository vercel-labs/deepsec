import { spawn } from "node:child_process";
import { readFile, unlink } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { atomicWriteFile } from "../atomic-file.js";
import { loadEnvFile, parseEnvFile, updateEnvFile } from "../env-file.js";
import { type SetupAction, SetupProtocolError } from "../setup/protocol.js";

export const TESTED_VERCEL_CLI_VERSION = "56.3.2";

export interface VercelProjectLink {
  orgId: string;
  projectId: string;
  projectName?: string;
}

export interface CommandResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export type RunVercelCli = (args: string[], cwd: string) => Promise<CommandResult>;

export interface EnsureVercelLinkOptions {
  workspaceDir: string;
  interactive: boolean;
  env?: NodeJS.ProcessEnv;
  teamId?: string;
  projectId?: string;
  allowCreate?: boolean;
  projectName?: string;
  runCli?: RunVercelCli;
  onLog?: (message: string) => void;
}

export interface PlatformLinkResult {
  method: "existing-link" | "vercel-cli" | "access-token-triple";
  project: { teamId: string; projectId: string };
  link: VercelProjectLink;
}

function workspacePath(workspaceDir: string): string {
  if (!isAbsolute(workspaceDir)) throw new Error("workspaceDir must be absolute");
  return resolve(workspaceDir);
}

function shellArg(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

export function vercelAuthRecoveryActions(
  workspaceDir: string,
  alreadyLinked: boolean,
): SetupAction[] {
  return [
    {
      id: "vercel-login",
      description: "Ask the user to authenticate in a terminal, then continue setup.",
      commands: ["npx vercel login"],
    },
    ...(!alreadyLinked
      ? [
          {
            id: "vercel-link-workspace",
            description:
              "After login, have the agent link only Deepsec's isolated workspace. The interactive form lets the user choose a team and project.",
            commands: [`cd ${shellArg(workspaceDir)}`, "npx vercel link"],
          },
          {
            id: "vercel-link-known-project",
            description:
              "If the team slug and an existing project name are known, the agent can link without prompts.",
            commands: [
              `cd ${shellArg(workspaceDir)}`,
              "npx vercel link --yes --team <team-slug> --project <project-name>",
            ],
          },
        ]
      : []),
    {
      id: "access-token",
      description: "Provide a Vercel access-token credential triple instead.",
      requiredEnv: ["VERCEL_TOKEN", "VERCEL_TEAM_ID", "VERCEL_PROJECT_ID"],
    },
  ];
}

export async function readWorkspaceLink(workspaceDir: string): Promise<VercelProjectLink | null> {
  const file = join(workspacePath(workspaceDir), ".vercel", "project.json");
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(file, "utf8"));
  } catch (error: any) {
    if (error?.code === "ENOENT") return null;
    throw new Error(`Invalid workspace Vercel link at ${file}`);
  }
  if (
    !parsed ||
    typeof parsed !== "object" ||
    typeof (parsed as any).orgId !== "string" ||
    !(parsed as any).orgId ||
    typeof (parsed as any).projectId !== "string" ||
    !(parsed as any).projectId
  ) {
    throw new Error(`Invalid workspace Vercel link at ${file}`);
  }
  return parsed as VercelProjectLink;
}

async function writeWorkspaceLink(workspaceDir: string, link: VercelProjectLink): Promise<void> {
  const file = join(workspacePath(workspaceDir), ".vercel", "project.json");
  await atomicWriteFile(file, `${JSON.stringify(link, null, 2)}\n`, { mode: 0o600 });
}

export const runPinnedVercelCli: RunVercelCli = async (args, cwd) =>
  await new Promise((resolvePromise, reject) => {
    const capture = args.includes("--format=json");
    const child = spawn("npx", ["--yes", `vercel@${TESTED_VERCEL_CLI_VERSION}`, ...args], {
      cwd,
      env: process.env,
      stdio: capture ? ["ignore", "pipe", "pipe"] : "inherit",
    });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const finish = (result: CommandResult) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolvePromise(result);
    };
    const fail = (error: Error) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      reject(error);
    };
    const timer = capture
      ? setTimeout(() => {
          child.stdout?.destroy();
          child.stderr?.destroy();
          child.kill("SIGTERM");
          fail(new Error(`vercel ${args.slice(0, 2).join(" ")} timed out after 45 seconds`));
        }, 45_000)
      : undefined;
    timer?.unref();
    child.stdout?.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });
    child.once("error", fail);
    child.once("close", (code) => finish({ exitCode: code ?? 1, stdout, stderr }));
  });

function parseJsonOutput(result: CommandResult, label: string): Record<string, any> {
  if (result.exitCode !== 0) throw new Error(`${label} failed with exit ${result.exitCode}`);
  const start = result.stdout.indexOf("{");
  const end = result.stdout.lastIndexOf("}");
  if (start < 0 || end <= start) throw new Error(`${label} did not return JSON`);
  return JSON.parse(result.stdout.slice(start, end + 1));
}

interface VercelTeam {
  id: string;
  slug: string;
  name: string;
  current?: boolean;
}

interface ListedVercelProject {
  id: string;
  name: string;
}

async function listTeams(runCli: RunVercelCli, cwd: string): Promise<VercelTeam[]> {
  const teams = parseJsonOutput(
    await runCli(["teams", "list", "--format=json", "--limit", "100"], cwd),
    "vercel teams list",
  ).teams;
  if (!Array.isArray(teams) || teams.length === 0) throw new Error("No Vercel teams are available");
  return teams as VercelTeam[];
}

async function listProjects(
  runCli: RunVercelCli,
  cwd: string,
  teamSlug: string,
): Promise<ListedVercelProject[]> {
  const value = parseJsonOutput(
    await runCli(["project", "list", "--format=json", "--limit", "100", "--scope", teamSlug], cwd),
    "vercel project list",
  );
  return (value.projects ?? []) as ListedVercelProject[];
}

async function addProject(
  runCli: RunVercelCli,
  cwd: string,
  teamSlug: string,
  projectName: string,
): Promise<void> {
  await requireSuccess(
    await runCli(["project", "add", projectName, "--scope", teamSlug], cwd),
    "vercel project add",
  );
}

async function linkProject(
  runCli: RunVercelCli,
  cwd: string,
  teamSlug: string,
  projectName: string,
): Promise<void> {
  await requireSuccess(
    await runCli(["link", "--yes", "--team", teamSlug, "--project", projectName], cwd),
    "vercel link",
  );
}

async function promptForProjectLink(workspaceDir: string, runCli: RunVercelCli): Promise<void> {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    await requireSuccess(await runCli(["link", "--yes"], workspaceDir), "vercel link");
    return;
  }
  const teams = await listTeams(runCli, workspaceDir);
  const currentIndex = Math.max(
    0,
    teams.findIndex((team) => team.current),
  );
  const prompt = createInterface({ input: process.stdin, output: process.stdout });
  try {
    console.log(
      "\nDeepsec links only its isolated .deepsec workspace. It does not deploy your application.",
    );
    console.log("The link provides workspace identity and makes Sandbox available later.\n");
    for (const [index, team] of teams.entries()) {
      console.log(`  ${index + 1}. ${team.name} (${team.slug})${team.current ? " [current]" : ""}`);
    }
    const teamAnswer = await prompt.question(`\nVercel team [${currentIndex + 1}]: `);
    const teamIndex = teamAnswer.trim() ? Number(teamAnswer) - 1 : currentIndex;
    const team = teams[teamIndex];
    if (!team) throw new Error("Invalid Vercel team selection");

    const projects = await listProjects(runCli, workspaceDir, team.slug);
    console.log("\n  1. Create a dedicated Deepsec project (recommended)");
    for (const [index, project] of projects.entries()) {
      console.log(`  ${index + 2}. ${project.name}`);
    }
    const projectAnswer = await prompt.question("\nVercel project [1]: ");
    const projectIndex = projectAnswer.trim() ? Number(projectAnswer) - 1 : 0;
    let projectName: string;
    if (projectIndex === 0) {
      const defaultName = `deepsec-${Math.random().toString(36).slice(2, 6)}`;
      const nameAnswer = await prompt.question(`Project name [${defaultName}]: `);
      projectName = nameAnswer.trim() || defaultName;
      await addProject(runCli, workspaceDir, team.slug, projectName);
    } else {
      const project = projects[projectIndex - 1];
      if (!project) throw new Error("Invalid Vercel project selection");
      projectName = project.name;
    }
    await linkProject(runCli, workspaceDir, team.slug, projectName);
  } finally {
    prompt.close();
  }
}

async function requireSuccess(result: CommandResult, action: string): Promise<void> {
  if (result.exitCode === 0) return;
  throw new Error(`${action} failed with exit ${result.exitCode}`);
}

async function pullOidcToken(
  workspaceDir: string,
  runCli: RunVercelCli,
  env: NodeJS.ProcessEnv,
): Promise<void> {
  const temp = join(workspaceDir, `.deepsec-vercel-env-${process.pid}-${Date.now()}`);
  try {
    await requireSuccess(
      await runCli(["env", "pull", temp, "--yes"], workspaceDir),
      "vercel env pull",
    );
    const pulled = parseEnvFile(await readFile(temp, "utf8"));
    if (!pulled.VERCEL_OIDC_TOKEN) {
      throw new Error("vercel env pull did not return VERCEL_OIDC_TOKEN");
    }
    await updateEnvFile(join(workspaceDir, ".env.local"), {
      VERCEL_OIDC_TOKEN: pulled.VERCEL_OIDC_TOKEN,
    });
    env.VERCEL_OIDC_TOKEN = pulled.VERCEL_OIDC_TOKEN;
  } finally {
    await unlink(temp).catch(() => undefined);
  }
}

export async function ensureVercelLink(
  options: EnsureVercelLinkOptions,
): Promise<PlatformLinkResult> {
  const workspaceDir = workspacePath(options.workspaceDir);
  const env = options.env ?? process.env;
  const existing = await readWorkspaceLink(workspaceDir);
  await loadEnvFile(join(workspaceDir, ".env.local"), env);

  if (!options.interactive) {
    if (existing && env.VERCEL_OIDC_TOKEN) {
      env.VERCEL_TEAM_ID = existing.orgId;
      env.VERCEL_PROJECT_ID = existing.projectId;
      return {
        method: "existing-link",
        project: { teamId: existing.orgId, projectId: existing.projectId },
        link: existing,
      };
    }
    const explicitTeamId = options.teamId ?? env.VERCEL_TEAM_ID;
    const explicitProjectId = options.projectId ?? env.VERCEL_PROJECT_ID;
    const teamId = explicitTeamId ?? existing?.orgId;
    const projectId = explicitProjectId ?? existing?.projectId;
    if (env.VERCEL_TOKEN && teamId && projectId) {
      if (!existing || existing.orgId !== teamId || existing.projectId !== projectId) {
        await writeWorkspaceLink(workspaceDir, { orgId: teamId, projectId });
      }
      env.VERCEL_TEAM_ID = teamId;
      env.VERCEL_PROJECT_ID = projectId;
      return {
        method: "access-token-triple",
        project: { teamId, projectId },
        link: { orgId: teamId, projectId },
      };
    }

    const runCli = options.runCli ?? runPinnedVercelCli;
    const whoami = await runCli(["whoami"], workspaceDir);
    if (whoami.exitCode !== 0) {
      throw new SetupProtocolError({
        code: "VERCEL_AUTH_REQUIRED",
        message:
          "Deepsec needs the user to authenticate with Vercel before headless setup can continue.",
        missingInputs: ["vercel.authentication"],
        actions: vercelAuthRecoveryActions(workspaceDir, existing !== null),
      });
    }

    if (existing) {
      try {
        await pullOidcToken(workspaceDir, runCli, env);
      } catch (error) {
        throw new SetupProtocolError({
          code: "VERCEL_OIDC_REFRESH_FAILED",
          message:
            "Vercel is logged in, but Deepsec could not refresh the linked workspace credential.",
          missingInputs: ["vercel.workspaceCredential"],
          actions: [
            {
              id: "refresh-oidc",
              description: "Refresh the linked workspace environment, then resume setup.",
              commands: [`cd ${workspaceDir}`, "npx vercel env pull .env.local --yes"],
            },
          ],
          details: { cause: error instanceof Error ? error.message : String(error) },
        });
      }
      return {
        method: "existing-link",
        project: { teamId: existing.orgId, projectId: existing.projectId },
        link: existing,
      };
    }

    if (explicitTeamId && explicitProjectId) {
      const link = { orgId: explicitTeamId, projectId: explicitProjectId };
      await writeWorkspaceLink(workspaceDir, link);
      try {
        await pullOidcToken(workspaceDir, runCli, env);
      } catch (error) {
        throw new SetupProtocolError({
          code: "VERCEL_PROJECT_ACCESS_FAILED",
          message: "The authenticated Vercel CLI could not access the requested team/project.",
          missingInputs: ["vercel.projectAccess"],
          details: { cause: error instanceof Error ? error.message : String(error) },
        });
      }
      return {
        method: "vercel-cli",
        project: { teamId: explicitTeamId, projectId: explicitProjectId },
        link,
      };
    }

    const teams = await listTeams(runCli, workspaceDir);
    const requestedTeam = explicitTeamId
      ? teams.find((team) => team.id === explicitTeamId || team.slug === explicitTeamId)
      : undefined;
    // A CLI's current team is ambient local state, not a headless user's
    // selection. Only auto-select when there is exactly one possible team;
    // otherwise return structured choices so the driving agent can ask.
    const team = requestedTeam ?? (teams.length === 1 ? teams[0] : undefined);
    if (!team) {
      throw new SetupProtocolError({
        code: "VERCEL_SCOPE_REQUIRED",
        message:
          "Ask the user which Vercel team should own the isolated Deepsec project, then resume with their selection.",
        missingInputs: ["vercel.teamId"],
        choices: teams.map((candidate) => ({
          value: candidate.id,
          label: `${candidate.name} (${candidate.slug})`,
          recommended: candidate.current === true,
        })),
        actions: [
          {
            id: "select-team",
            description: "Resume with the selected team ID.",
            resumeArgs: ["--vercel-team-id", "<choice>"],
          },
        ],
      });
    }
    if (!options.allowCreate) {
      throw new SetupProtocolError({
        code: "VERCEL_PROJECT_CREATION_APPROVAL_REQUIRED",
        message:
          "Headless setup is ready to create or reuse a dedicated Vercel project, but requires --yes.",
        missingInputs: ["vercel.projectCreationApproval"],
        actions: [
          {
            id: "approve-project",
            description: "Allow deterministic dedicated-project creation and resume setup.",
            resumeArgs: ["--yes", "--vercel-team-id", team.id],
          },
        ],
      });
    }

    const projectName = options.projectName;
    if (!projectName) throw new Error("Headless project creation requires a deterministic name");
    const projects = await listProjects(runCli, workspaceDir, team.slug);
    let project = projects.find((candidate) => candidate.name === projectName);
    if (!project) {
      await addProject(runCli, workspaceDir, team.slug, projectName);
      const refreshed = await listProjects(runCli, workspaceDir, team.slug);
      project = refreshed.find((candidate) => candidate.name === projectName);
    }
    if (!project)
      throw new Error(`Vercel project ${projectName} was created but could not be found`);
    await linkProject(runCli, workspaceDir, team.slug, projectName);
    await pullOidcToken(workspaceDir, runCli, env);
    const link = (await readWorkspaceLink(workspaceDir)) ?? {
      orgId: team.id,
      projectId: project.id,
      projectName,
    };
    return {
      method: "vercel-cli",
      project: { teamId: link.orgId, projectId: link.projectId },
      link,
    };
  }

  const runCli = options.runCli ?? runPinnedVercelCli;
  let method: PlatformLinkResult["method"] = "existing-link";
  if (!existing) {
    options.onLog?.(
      "Now we're linking Deepsec to a Vercel project for AI Gateway access. Because the link reads the project's development environment, a dedicated empty Deepsec project is safest.",
    );
    const whoami = await runCli(["whoami"], workspaceDir);
    if (whoami.exitCode !== 0) {
      await requireSuccess(await runCli(["login"], workspaceDir), "vercel login");
    }
    if (options.runCli) {
      await requireSuccess(await runCli(["link", "--yes"], workspaceDir), "vercel link");
    } else {
      await promptForProjectLink(workspaceDir, runCli);
    }
    method = "vercel-cli";
  }

  let link = await readWorkspaceLink(workspaceDir);
  if (!link)
    throw new Error("vercel link completed without writing workspace/.vercel/project.json");

  // `vercel link` (or a test/integration wrapper around it) may have
  // materialized the workspace credential after our initial env load.
  await loadEnvFile(join(workspaceDir, ".env.local"), env);
  if (!env.VERCEL_OIDC_TOKEN) {
    try {
      await pullOidcToken(workspaceDir, runCli, env);
    } catch {
      await requireSuccess(await runCli(["login"], workspaceDir), "vercel login");
      await pullOidcToken(workspaceDir, runCli, env);
    }
  }

  link = (await readWorkspaceLink(workspaceDir))!;
  return {
    method,
    project: { teamId: link.orgId, projectId: link.projectId },
    link,
  };
}

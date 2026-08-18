import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";

const ROOT = path.resolve(import.meta.dirname, "..");
const BUNDLE = path.join(ROOT, "packages/deepsec/dist/cli.mjs");
const FIXTURES = path.join(ROOT, "fixtures/vulnerable-app");

function runBundle(
  args: string[],
  opts: { cwd?: string; env?: Record<string, string> } = {},
): { stdout: string; stderr: string; status: number } {
  const result = spawnSync("node", [BUNDLE, ...args], {
    cwd: opts.cwd ?? ROOT,
    env: { ...process.env, ...(opts.env ?? {}) },
    encoding: "utf-8",
    timeout: 60_000,
  });
  return {
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    status: result.status ?? -1,
  };
}

function makeWorkspace(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-bundle-"));
  // Symlink the repo's node_modules so the temp workspace can resolve
  // `deepsec/config` (workspace symlink) and the externalized native deps.
  fs.symlinkSync(path.join(ROOT, "node_modules"), path.join(dir, "node_modules"), "dir");
  return dir;
}

describe("bundle e2e", () => {
  beforeAll(() => {
    if (!fs.existsSync(BUNDLE)) {
      throw new Error(`Bundle not found at ${BUNDLE}. Run \`pnpm bundle\` first.`);
    }
  });

  it("--help exits 0 and prints the help banner", () => {
    const { stdout, status } = runBundle(["--help"]);
    expect(status).toBe(0);
    expect(stdout).toContain("deepsec");
    expect(stdout).toContain("scan");
    expect(stdout).toContain("process");
  });

  it("config.d.ts is self-contained (no internal @deepsec/* re-exports)", () => {
    const dts = fs.readFileSync(path.join(ROOT, "packages/deepsec/dist/config.d.ts"), "utf-8");
    // Consumers install only `deepsec` from npm — `@deepsec/core` and
    // `@deepsec/scanner` are workspace-internal. Any leaked re-export
    // here breaks typing for `import { defineConfig } from "deepsec/config"`.
    expect(dts).not.toMatch(/from\s+["']@deepsec\//);
  });

  it("ships the complete, internally linked agent documentation", () => {
    const packageRoot = path.join(ROOT, "packages/deepsec");
    const docsRoot = path.join(packageRoot, "dist/docs");
    const meta = JSON.parse(fs.readFileSync(path.join(docsRoot, "meta.json"), "utf-8")) as {
      pages: string[];
    };

    expect(fs.existsSync(path.join(packageRoot, "SKILL.md"))).toBe(true);
    for (const page of meta.pages) {
      expect(fs.existsSync(path.join(docsRoot, `${page}.md`)), page).toBe(true);
    }

    for (const file of fs.readdirSync(docsRoot).filter((name) => name.endsWith(".md"))) {
      const markdown = fs.readFileSync(path.join(docsRoot, file), "utf-8");
      for (const match of markdown.matchAll(/\[[^\]]*\]\(([^)]+)\)/g)) {
        const target = match[1].split("#")[0];
        if (!target || /^(?:https?:|mailto:)/.test(target)) continue;
        expect(
          fs.existsSync(path.resolve(docsRoot, path.dirname(file), target)),
          `${file}: ${target}`,
        ).toBe(true);
      }
    }
  });

  it("--version reports the current package version", () => {
    const { stdout, status } = runBundle(["--version"]);
    expect(status).toBe(0);
    const deepsecPkg = JSON.parse(
      fs.readFileSync(path.join(ROOT, "packages/deepsec/package.json"), "utf-8"),
    );
    expect(stdout.trim()).toBe(deepsecPkg.version);
  });

  it("scan against the fixture produces FileRecords", () => {
    const cwd = makeWorkspace();
    fs.writeFileSync(
      path.join(cwd, "deepsec.config.ts"),
      `import { defineConfig } from "deepsec/config";
export default defineConfig({
  projects: [{ id: "fixture", root: ${JSON.stringify(FIXTURES)} }],
});`,
    );

    const { status, stdout, stderr } = runBundle(
      ["scan", "--project-id", "fixture", "--root", FIXTURES],
      { cwd },
    );
    expect(status, `stdout: ${stdout}\nstderr: ${stderr}`).toBe(0);
    expect(stdout).toContain("Scan complete");

    const filesDir = path.join(cwd, "data", "fixture", "files");
    expect(fs.existsSync(filesDir)).toBe(true);
    const filesCount = fs.readdirSync(filesDir, { recursive: true }).length;
    expect(filesCount).toBeGreaterThan(0);
  });

  it("loads deepsec.config.ts from cwd via the bundle", () => {
    const cwd = makeWorkspace();
    fs.writeFileSync(
      path.join(cwd, "deepsec.config.ts"),
      `import { defineConfig } from "deepsec/config";
console.error("[config-loaded-marker]");
export default defineConfig({
  projects: [{ id: "fixture", root: ${JSON.stringify(FIXTURES)} }],
});`,
    );

    const { stderr } = runBundle(["--help"], { cwd });
    expect(stderr).toContain("[config-loaded-marker]");
  });

  it("activates an inline plugin declared in deepsec.config.ts", () => {
    const cwd = makeWorkspace();
    // A throwaway plugin contributing one matcher. If the bundle's plugin
    // loader works, the matcher's slug should be selectable via --matchers
    // and visible in the scan log.
    fs.writeFileSync(
      path.join(cwd, "deepsec.config.ts"),
      `import { defineConfig } from "deepsec/config";
const plugin = {
  name: "inline-test-plugin",
  matchers: [{
    slug: "inline-test-matcher",
    description: "test marker",
    noiseTier: "precise",
    filePatterns: ["**/*.ts"],
    match() { return []; },
  }],
};
export default defineConfig({
  projects: [{ id: "fixture", root: ${JSON.stringify(FIXTURES)} }],
  plugins: [plugin],
});`,
    );

    const { status, stdout } = runBundle(
      ["scan", "--project-id", "fixture", "--root", FIXTURES, "--matchers", "inline-test-matcher"],
      { cwd },
    );
    expect(status, stdout).toBe(0);
    expect(stdout).toContain("inline-test-matcher");
  });

  it("samples/webapp/ — config loads and custom matchers register", () => {
    const sampleDir = path.join(ROOT, "samples/webapp");
    // Symlink node_modules so the sample's `deepsec/config` import resolves.
    const link = path.join(sampleDir, "node_modules");
    if (!fs.existsSync(link)) {
      fs.symlinkSync(path.join(ROOT, "node_modules"), link, "dir");
    }
    try {
      const { status, stdout, stderr } = runBundle(
        [
          "scan",
          "--project-id",
          "webapp",
          "--root",
          FIXTURES,
          "--matchers",
          "webapp-debug-flag,webapp-route-no-rate-limit",
        ],
        { cwd: sampleDir },
      );
      expect(status, `stdout: ${stdout}\nstderr: ${stderr}`).toBe(0);
      // Both custom matchers should appear in the run log.
      expect(stdout).toContain("webapp-debug-flag");
      expect(stdout).toContain("webapp-route-no-rate-limit");
    } finally {
      fs.rmSync(link, { force: true });
      fs.rmSync(path.join(sampleDir, "data"), { recursive: true, force: true });
    }
  });

  it("init --plan is read-only and emits machine-readable setup intent", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-plan-e2e-"));
    const targetRoot = path.join(tmp, "app");
    const workspace = path.join(tmp, ".deepsec");
    fs.mkdirSync(targetRoot);
    fs.writeFileSync(path.join(targetRoot, "index.ts"), "export const value = 1;\n");

    const result = runBundle(
      [
        "init",
        workspace,
        targetRoot,
        "--plan",
        "--model",
        "gpt-5.6-sol",
        "--agent",
        "codex",
        "--output",
        "json",
      ],
      {
        env: {
          VERCEL_TOKEN: "test-token",
          VERCEL_TEAM_ID: "team_test",
          VERCEL_PROJECT_ID: "prj_test",
        },
      },
    );

    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject({
      type: "plan",
      repository: { id: "app", files: 1 },
      workspace: { exists: false },
    });
    expect(fs.existsSync(workspace)).toBe(false);
  });

  it("headless init returns structured model input instead of prompting", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-headless-e2e-"));
    const targetRoot = path.join(tmp, "app");
    const workspace = path.join(tmp, ".deepsec");
    fs.mkdirSync(targetRoot);

    const result = runBundle(["init", workspace, targetRoot, "--output", "json"]);

    expect(result.status).toBe(2);
    expect(JSON.parse(result.stdout)).toMatchObject({
      type: "needs_input",
      code: "MODEL_SELECTION_REQUIRED",
      missingInputs: ["model.profile"],
      documentation: {
        skill: path.join(workspace, "node_modules", "deepsec", "SKILL.md"),
        gettingStarted: path.join(
          workspace,
          "node_modules",
          "deepsec",
          "dist",
          "docs",
          "getting-started.md",
        ),
      },
    });
    expect(result.stdout).not.toContain("Model access");
  });

  it("human-mode needs-input errors use the resumable exit code without a crash hint", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-headless-human-e2e-"));
    const targetRoot = path.join(tmp, "app");
    const workspace = path.join(tmp, ".deepsec");
    fs.mkdirSync(targetRoot);

    const result = runBundle(["init", workspace, targetRoot]);

    expect(result.status).toBe(2);
    expect(result.stderr).toContain("MODEL_SELECTION_REQUIRED");
    expect(result.stderr).not.toContain("DEEPSEC_DEBUG");
  });

  it("rejects a bare --max-duration instead of treating it as milliseconds", () => {
    const result = runBundle(["init", "--max-duration", "30"]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Duration must look like 500ms, 30s, 10m, or 2h");
  });

  it("init --scaffold-only writes a workspace seeded with the first project", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-init-"));
    const workspace = path.join(tmp, "audits");
    const targetRoot = path.join(tmp, "my-app");
    fs.mkdirSync(targetRoot);
    try {
      const { status, stdout, stderr } = runBundle([
        "init",
        workspace,
        targetRoot,
        "--scaffold-only",
      ]);
      expect(status, `stdout: ${stdout}\nstderr: ${stderr}`).toBe(0);
      expect(stdout).toContain("Created");
      expect(stdout).toContain("First project:");
      expect(stdout).toContain("Paste this into your coding agent");
      expect(stdout).toContain("SKILL.md");
      expect(stdout).toContain("data/my-app/INFO.md");

      for (const f of [
        "package.json",
        "deepsec.config.ts",
        "README.md",
        "AGENTS.md",
        ".gitignore",
        "data/my-app/INFO.md",
        "data/my-app/SETUP.md",
        "data/my-app/project.json",
      ]) {
        expect(fs.existsSync(path.join(workspace, f)), `missing ${f}`).toBe(true);
      }
      expect(fs.existsSync(path.join(workspace, ".env.local"))).toBe(false);
      // No top-level INFO.md / SETUP.md — both live under data/<id>/.
      expect(fs.existsSync(path.join(workspace, "INFO.md"))).toBe(false);
      expect(fs.existsSync(path.join(workspace, "SETUP.md"))).toBe(false);
      // No custom matchers / extra files from a sample copy.
      expect(fs.existsSync(path.join(workspace, "matchers"))).toBe(false);
      expect(fs.existsSync(path.join(workspace, "config.json"))).toBe(false);

      // package.json: workspace dir name + the exact CLI package. A bundle
      // launched from this source checkout must install the checkout itself,
      // rather than an older npm artifact with the same package version.
      const pkg = JSON.parse(fs.readFileSync(path.join(workspace, "package.json"), "utf-8"));
      expect(pkg.name).toBe("audits");
      const localDependency = pathToFileURL(path.join(ROOT, "packages/deepsec")).href;
      expect(pkg.dependencies.deepsec).toBe(localDependency);

      // A local bundle must also repair a workspace produced by an earlier
      // run that accidentally pointed at the registry package. This is the
      // exact recovery path after install succeeded but config loading failed.
      pkg.dependencies.deepsec = "^2.2.9";
      fs.writeFileSync(path.join(workspace, "package.json"), `${JSON.stringify(pkg, null, 2)}\n`);
      const resumed = runBundle(["init", workspace, targetRoot, "--scaffold-only"]);
      expect(resumed.status, `stdout: ${resumed.stdout}\nstderr: ${resumed.stderr}`).toBe(0);
      expect(resumed.stdout).toContain("Resuming");
      const repairedPkg = JSON.parse(
        fs.readFileSync(path.join(workspace, "package.json"), "utf-8"),
      );
      expect(repairedPkg.dependencies.deepsec).toBe(localDependency);
      // packageManager: pinned to pnpm so a parent repo's `packageManager`
      // (e.g. yarn) doesn't make pnpm refuse to install in `.deepsec/`.
      expect(pkg.packageManager).toMatch(/^pnpm@\d+\.\d+\.\d+$/);

      // config.ts: minimal — id + root only, plus the insert marker.
      const configSrc = fs.readFileSync(path.join(workspace, "deepsec.config.ts"), "utf-8");
      expect(configSrc).toContain('id: "my-app"');
      expect(configSrc).toContain('root: "../my-app"');
      expect(configSrc).toContain("// <deepsec:projects-insert-above>");
      expect(configSrc).not.toContain("<deepsec:model-route>");
      expect(configSrc).not.toMatch(/^\s*ai\s*:/m);
      expect(configSrc).not.toContain("infoMarkdown");
      expect(configSrc).not.toContain('from "node:fs"');

      // README.md: usage instructions for humans.
      const readmeMd = fs.readFileSync(path.join(workspace, "README.md"), "utf-8");
      expect(readmeMd).toContain("# deepsec");
      expect(readmeMd).toContain("pnpm deepsec scan");
      expect(readmeMd).toContain("init-project");

      // AGENTS.md: workspace-level pointer (no per-project content).
      const agentsMd = fs.readFileSync(path.join(workspace, "AGENTS.md"), "utf-8");
      expect(agentsMd).toContain("node_modules/deepsec/SKILL.md");
      expect(agentsMd).toContain("data/<id>/SETUP.md");
      expect(agentsMd).toContain("init-project");
      // AGENTS.md itself doesn't mention any specific project.
      expect(agentsMd).not.toContain("my-app");

      // SETUP.md: per-project setup prompt with target paths.
      const setupMd = fs.readFileSync(path.join(workspace, "data/my-app/SETUP.md"), "utf-8");
      expect(setupMd).toContain("`my-app`");
      expect(setupMd).toContain("../my-app");
      expect(setupMd).toContain("node_modules/deepsec/SKILL.md");
      expect(setupMd).toContain("data/my-app/INFO.md");

      // project.json populated with rootPath.
      const projectJson = JSON.parse(
        fs.readFileSync(path.join(workspace, "data/my-app/project.json"), "utf-8"),
      );
      expect(projectJson.projectId).toBe("my-app");
      expect(projectJson.rootPath).toBeTruthy();

      // .gitignore: keeps INFO.md/SETUP.md trackable, ignores generated state.
      const gitignore = fs.readFileSync(path.join(workspace, ".gitignore"), "utf-8");
      expect(gitignore).toContain("data/*/files/");
      expect(gitignore).toContain("data/*/runs/");
      expect(gitignore).toContain("data/*/project.json");
      expect(gitignore).toContain("data/*/setup/");
      expect(gitignore).toContain(".vercel/");
      // Bare `data/` line should NOT be present — that would shadow INFO.md.
      expect(gitignore).not.toMatch(/^data\/$/m);

      const otherParent = path.join(tmp, "fork");
      const sameNamedTarget = path.join(otherParent, "my-app");
      fs.mkdirSync(sameNamedTarget, { recursive: true });
      const mismatchedResume = runBundle(["init", workspace, sameNamedTarget, "--scaffold-only"]);
      expect(mismatchedResume.status).not.toBe(0);
      expect(mismatchedResume.stderr).toContain("different target root");
      expect(mismatchedResume.stderr).toContain(targetRoot);
      expect(mismatchedResume.stderr).toContain(sameNamedTarget);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("repairs a truncated generated project registration with --force", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-init-repair-"));
    const workspace = path.join(tmp, ".deepsec");
    const targetRoot = path.join(tmp, "app");
    fs.mkdirSync(targetRoot);
    expect(runBundle(["init", workspace, targetRoot, "--scaffold-only"]).status).toBe(0);
    const projectFile = path.join(workspace, "data", "app", "project.json");
    fs.writeFileSync(projectFile, '{"projectId":');

    const failed = runBundle(["init", workspace, targetRoot, "--scaffold-only"]);
    expect(failed.status).toBe(1);
    expect(failed.stderr).toContain("Rerun with --force to repair");

    const repaired = runBundle(["init", workspace, targetRoot, "--scaffold-only", "--force"]);
    expect(repaired.status, repaired.stderr).toBe(0);
    expect(JSON.parse(fs.readFileSync(projectFile, "utf8"))).toMatchObject({
      projectId: "app",
      rootPath: fs.realpathSync(targetRoot),
    });
  });

  it("init with no args defaults to .deepsec/ inside cwd, target = .", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-init-"));
    const repo = path.join(tmp, "my-repo");
    fs.mkdirSync(repo);
    fs.writeFileSync(path.join(repo, "package.json"), "{}\n");
    try {
      const { status, stdout, stderr } = runBundle(["init", "--scaffold-only"], { cwd: repo });
      expect(status, `stdout: ${stdout}\nstderr: ${stderr}`).toBe(0);
      // Workspace lands at .deepsec/ inside the repo.
      const workspace = path.join(repo, ".deepsec");
      expect(fs.existsSync(path.join(workspace, "deepsec.config.ts"))).toBe(true);
      // Project id is derived from cwd basename.
      expect(fs.existsSync(path.join(workspace, "data/my-repo/INFO.md"))).toBe(true);
      // Config's `root` is the parent (target = .).
      const configSrc = fs.readFileSync(path.join(workspace, "deepsec.config.ts"), "utf-8");
      expect(configSrc).toContain('id: "my-repo"');
      expect(configSrc).toContain('root: ".."');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("init --id overrides the auto-derived project id", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-init-"));
    const workspace = path.join(tmp, "audits");
    const targetRoot = path.join(tmp, "boring-name");
    fs.mkdirSync(targetRoot);
    try {
      const { status, stdout, stderr } = runBundle([
        "init",
        workspace,
        targetRoot,
        "--id",
        "internal-api",
        "--scaffold-only",
      ]);
      expect(status, `stdout: ${stdout}\nstderr: ${stderr}`).toBe(0);
      const configSrc = fs.readFileSync(path.join(workspace, "deepsec.config.ts"), "utf-8");
      expect(configSrc).toContain('id: "internal-api"');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("init refuses a non-existent target codebase", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-init-"));
    try {
      const { status, stderr } = runBundle([
        "init",
        path.join(tmp, "audits"),
        path.join(tmp, "does-not-exist"),
      ]);
      expect(status).not.toBe(0);
      expect(stderr).toContain("Path does not exist");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("init refuses a non-empty workspace without --force", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-init-"));
    const workspace = path.join(tmp, "audits");
    const targetRoot = path.join(tmp, "my-app");
    fs.mkdirSync(workspace);
    fs.mkdirSync(targetRoot);
    fs.writeFileSync(path.join(workspace, "marker"), "");
    try {
      const { status, stderr } = runBundle(["init", workspace, targetRoot]);
      expect(status).not.toBe(0);
      expect(stderr).toContain("not empty");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("init-project adds a second project to an existing workspace", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-init-"));
    const workspace = path.join(tmp, "audits");
    const firstTarget = path.join(tmp, "first-app");
    const secondTarget = path.join(tmp, "second-app");
    fs.mkdirSync(firstTarget);
    fs.mkdirSync(secondTarget);
    try {
      const init = runBundle(["init", workspace, firstTarget, "--scaffold-only"]);
      expect(init.status, `init: ${init.stdout}\n${init.stderr}`).toBe(0);

      // Run init-project from inside the workspace (changes cwd via spawn).
      const ip = runBundle(["init-project", secondTarget], { cwd: workspace });
      expect(ip.status, `init-project: ${ip.stdout}\n${ip.stderr}`).toBe(0);
      expect(ip.stdout).toContain("Added project");
      expect(ip.stdout).toContain("second-app");

      // Both entries above the marker.
      const configSrc = fs.readFileSync(path.join(workspace, "deepsec.config.ts"), "utf-8");
      expect(configSrc).toContain('id: "first-app"');
      expect(configSrc).toContain('id: "second-app"');
      const firstIdx = configSrc.indexOf('id: "first-app"');
      const secondIdx = configSrc.indexOf('id: "second-app"');
      const markerIdx = configSrc.indexOf("// <deepsec:projects-insert-above>");
      expect(firstIdx).toBeGreaterThan(0);
      expect(secondIdx).toBeGreaterThan(firstIdx);
      expect(markerIdx).toBeGreaterThan(secondIdx);

      // Both projects have data dirs.
      for (const f of [
        "data/first-app/INFO.md",
        "data/first-app/SETUP.md",
        "data/first-app/project.json",
        "data/second-app/INFO.md",
        "data/second-app/SETUP.md",
        "data/second-app/project.json",
      ]) {
        expect(fs.existsSync(path.join(workspace, f)), `missing ${f}`).toBe(true);
      }
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("init-project errors on missing target codebase", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-init-"));
    const workspace = path.join(tmp, "audits");
    const target = path.join(tmp, "first");
    fs.mkdirSync(target);
    try {
      runBundle(["init", workspace, target, "--scaffold-only"]);
      const { status, stderr } = runBundle(["init-project", path.join(tmp, "does-not-exist")], {
        cwd: workspace,
      });
      expect(status).not.toBe(0);
      expect(stderr).toContain("Path does not exist");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("init-project errors on duplicate project id without --force", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-init-"));
    const workspace = path.join(tmp, "audits");
    const target = path.join(tmp, "my-app");
    fs.mkdirSync(target);
    try {
      runBundle(["init", workspace, target, "--scaffold-only"]);
      // Re-add the same target → same id ("my-app") → collision.
      const { status, stderr } = runBundle(["init-project", target], { cwd: workspace });
      expect(status).not.toBe(0);
      expect(stderr).toContain("already exists");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("init-project errors when run outside a deepsec workspace", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-init-"));
    const target = path.join(tmp, "my-app");
    fs.mkdirSync(target);
    try {
      const { status, stderr } = runBundle(["init-project", target], { cwd: tmp });
      expect(status).not.toBe(0);
      expect(stderr).toContain("No .deepsec/ workspace");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("init-project errors when the marker is missing from deepsec.config.ts", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-init-"));
    const workspace = path.join(tmp, "audits");
    const firstTarget = path.join(tmp, "first");
    const secondTarget = path.join(tmp, "second");
    fs.mkdirSync(firstTarget);
    fs.mkdirSync(secondTarget);
    try {
      runBundle(["init", workspace, firstTarget, "--scaffold-only"]);
      // Strip the marker out of the config.
      const cfgPath = path.join(workspace, "deepsec.config.ts");
      const stripped = fs
        .readFileSync(cfgPath, "utf-8")
        .replace(/\s*\/\/ <deepsec:projects-insert-above>/g, "");
      fs.writeFileSync(cfgPath, stripped);

      const { status, stderr } = runBundle(["init-project", secondTarget], { cwd: workspace });
      expect(status).not.toBe(0);
      expect(stderr).toContain("Marker");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("scan resolves --root from the config when omitted (sibling layout)", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-init-"));
    const workspace = path.join(tmp, "audits");
    const targetRoot = path.join(tmp, "my-app");
    fs.mkdirSync(targetRoot);
    fs.writeFileSync(path.join(targetRoot, "app.ts"), 'console.log("hi");\n');
    try {
      const init = runBundle(["init", workspace, targetRoot, "--scaffold-only"]);
      expect(init.status, `init: ${init.stdout}\n${init.stderr}`).toBe(0);

      // Symlink node_modules so the freshly-init'd workspace can resolve
      // `deepsec/config` during config evaluation by jiti.
      fs.symlinkSync(path.join(ROOT, "node_modules"), path.join(workspace, "node_modules"), "dir");

      const scan = runBundle(["scan", "--project-id", "my-app"], { cwd: workspace });
      expect(scan.status, `scan: ${scan.stdout}\n${scan.stderr}`).toBe(0);
      expect(scan.stdout).toContain("Scan complete");
      // scan writes a run-meta entry; presence proves --root was resolved.
      const runsDir = path.join(workspace, "data/my-app/runs");
      expect(fs.existsSync(runsDir)).toBe(true);
      expect(fs.readdirSync(runsDir).length).toBeGreaterThan(0);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("scan resolves --root from the config (nested .deepsec/ layout)", () => {
    // Default `init` flow: workspace lands at .deepsec/ inside the codebase,
    // project root is ".." (the parent repo). Scan from inside .deepsec/
    // should resolve `..` against the workspace dir → the codebase itself.
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-init-"));
    const repo = path.join(tmp, "my-repo");
    fs.mkdirSync(repo);
    fs.writeFileSync(path.join(repo, "package.json"), "{}\n");
    fs.writeFileSync(path.join(repo, "app.ts"), 'console.log("hi");\n');
    try {
      const init = runBundle(["init", "--scaffold-only"], { cwd: repo });
      expect(init.status, `init: ${init.stdout}\n${init.stderr}`).toBe(0);

      const workspace = path.join(repo, ".deepsec");
      // Sanity: config.ts points at the parent repo via `..`.
      const configSrc = fs.readFileSync(path.join(workspace, "deepsec.config.ts"), "utf-8");
      expect(configSrc).toContain('root: ".."');

      fs.symlinkSync(path.join(ROOT, "node_modules"), path.join(workspace, "node_modules"), "dir");

      // No --project-id, no --root: both auto-resolve from the loaded config.
      const scan = runBundle(["scan"], { cwd: workspace });
      expect(scan.status, `scan: ${scan.stdout}\n${scan.stderr}`).toBe(0);
      expect(scan.stdout).toContain("Scan complete");

      // scan writes a run-meta entry; presence proves --root resolved.
      const runsDir = path.join(workspace, "data/my-repo/runs");
      expect(
        fs.existsSync(runsDir),
        `runsDir missing. scan stdout:\n${scan.stdout}\n--\nstderr:\n${scan.stderr}`,
      ).toBe(true);
      expect(fs.readdirSync(runsDir).length).toBeGreaterThan(0);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("scan errors clearly when --root is missing and no config / project.json", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-init-"));
    try {
      const { status, stderr } = runBundle(["scan", "--project-id", "ghost"], { cwd: tmp });
      expect(status).not.toBe(0);
      expect(stderr).toContain("No root path");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("scan auto-resolves --project-id when config has one project", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-init-"));
    const workspace = path.join(tmp, "audits");
    const targetRoot = path.join(tmp, "solo");
    fs.mkdirSync(targetRoot);
    fs.writeFileSync(path.join(targetRoot, "x.ts"), "export const y = 1;\n");
    try {
      runBundle(["init", workspace, targetRoot, "--scaffold-only"]);
      fs.symlinkSync(path.join(ROOT, "node_modules"), path.join(workspace, "node_modules"), "dir");
      // No --project-id flag — config has one project, auto-resolved.
      const { status, stdout, stderr } = runBundle(["scan"], { cwd: workspace });
      expect(status, `stdout: ${stdout}\nstderr: ${stderr}`).toBe(0);
      expect(stdout).toContain("Scanning");
      expect(stdout).toContain("for project");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("scan errors clearly when config has multiple projects and no --project-id", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-init-"));
    const workspace = path.join(tmp, "audits");
    const a = path.join(tmp, "a");
    const b = path.join(tmp, "b");
    fs.mkdirSync(a);
    fs.mkdirSync(b);
    try {
      runBundle(["init", workspace, a, "--scaffold-only"]);
      fs.symlinkSync(path.join(ROOT, "node_modules"), path.join(workspace, "node_modules"), "dir");
      // Append a second project entry above the marker.
      const cfgPath = path.join(workspace, "deepsec.config.ts");
      const orig = fs.readFileSync(cfgPath, "utf-8");
      const updated = orig.replace(
        /(\s*\/\/ <deepsec:projects-insert-above>)/,
        `\n    { id: "second", root: "../b" },$1`,
      );
      fs.writeFileSync(cfgPath, updated);

      const { status, stderr } = runBundle(["scan"], { cwd: workspace });
      expect(status).not.toBe(0);
      expect(stderr).toContain("Multiple projects");
      expect(stderr).toContain("Pass --project-id");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("scan errors clearly when --root points at a nonexistent path", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-init-"));
    try {
      const { status, stderr } = runBundle([
        "scan",
        "--project-id",
        "ghost",
        "--root",
        path.join(tmp, "no-such-dir"),
      ]);
      expect(status).not.toBe(0);
      expect(stderr).toContain("Path does not exist");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

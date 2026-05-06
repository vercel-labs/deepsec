/**
 * Live-sandbox sibling of pipeline.test.ts — runs init → scan →
 * sandbox process → sandbox revalidate against a real Vercel Sandbox,
 * but with a stub agent (same one as pipeline.test.ts). The point is
 * to validate the sandbox infrastructure end-to-end (bootstrap
 * snapshot, worker spawn, file upload/download, result merge), not the
 * model. No tokens are consumed.
 *
 * NOT run on push/PR: requires Vercel Sandbox credentials and takes
 * minutes. Two ways to run:
 *
 * 1. CI (recommended) — the dedicated workflow at
 *    `.github/workflows/e2e-live-sandbox.yml`. Trigger manually from
 *    GitHub Actions → "E2E live sandbox" → "Run workflow". Repo
 *    secrets needed: `VERCEL_TOKEN`, `VERCEL_TEAM_ID`,
 *    `VERCEL_PROJECT_ID`. (No AI key — the test uses a stub agent.)
 *
 * 2. Local — when iterating on sandbox code:
 *      VERCEL_OIDC_TOKEN=$(grep ^VERCEL_OIDC .deepsec/.env.local | cut -d= -f2) \
 *      DEEPSEC_E2E_LIVE_SANDBOX=1 \
 *        pnpm exec vitest run --project e2e e2e/pipeline-sandbox.test.ts
 *    (locally OIDC works; CI uses access tokens because OIDC is scoped
 *    to a Vercel deployment.)
 *
 * The test is `describe.skipIf` — without DEEPSEC_E2E_LIVE_SANDBOX=1
 * the entire file is silently skipped, so it stays out of the default
 * `pnpm test` run.
 *
 * Differences from pipeline.test.ts:
 *   - Calls `sandbox process` and `sandbox revalidate` (not the
 *     local in-process forms) — exercises sandbox bootstrap, snapshot,
 *     worker spawn, tarball upload/download, and result merge.
 *   - Same stub agent — the value isn't model output, it's the
 *     sandbox path. The proxy is intentionally NOT started for custom
 *     agents (see setup.ts), so this run needs no AI credentials.
 */

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { beforeAll, describe, expect, it } from "vitest";

const ROOT = path.resolve(import.meta.dirname, "..");
const FIXTURES = path.join(ROOT, "fixtures/vulnerable-app");

// We invoke the bundle through `tmp/node_modules/deepsec/dist/cli.mjs`
// (a symlink chain back to the source package) WITH
// `--preserve-symlinks-main`. That keeps `import.meta.url` at the
// node_modules path, so `resolveDeepsecAppContext` picks
// mode="installed" — same as production. In dev mode the appRoot
// would be the source repo (a git checkout), and `makeTarball`'s git
// branch would tarball ROOT itself, which is not what real users do
// AND tickles a tar arg-order interaction in CI's GNU tar.
const BUNDLE_REL = "node_modules/deepsec/dist/cli.mjs";

// Opt-in flag plus a sandbox-credential check so a typo doesn't burn
// 30s spinning up a sandbox that can't authenticate.
const LIVE = process.env.DEEPSEC_E2E_LIVE_SANDBOX === "1";
const HAS_SANDBOX_KEY =
  Boolean(process.env.VERCEL_OIDC_TOKEN) ||
  (Boolean(process.env.VERCEL_TOKEN) &&
    Boolean(process.env.VERCEL_TEAM_ID) &&
    Boolean(process.env.VERCEL_PROJECT_ID));

const SHOULD_RUN = LIVE && HAS_SANDBOX_KEY;

/**
 * Stub agent definition shared with pipeline.test.ts. Inlined here
 * because e2e files don't share imports — kept structurally identical
 * so divergence stays a code-review signal, not a hidden bug.
 */
const STUB_PLUGIN_SOURCE = `// stub-plugin.mjs — registers a deterministic agent named "stub"

const stub = {
  type: "stub",
  async *investigate(params) {
    yield { type: "started", message: "stub: starting" };
    return {
      results: params.batch.map((rec) => ({
        filePath: rec.filePath,
        findings: rec.candidates.length
          ? [{
              severity: "HIGH",
              vulnSlug: rec.candidates[0].vulnSlug,
              title: \`stub finding for \${rec.filePath}\`,
              description: "stub investigation result",
              lineNumbers: rec.candidates[0].lineNumbers ?? [1],
              recommendation: "stub: fix it",
              confidence: "medium",
            }]
          : [],
      })),
      meta: {
        durationMs: 1,
        usage: {
          inputTokens: 1,
          outputTokens: 1,
          cacheReadInputTokens: 0,
          cacheCreationInputTokens: 0,
        },
      },
    };
  },
  async *revalidate(params) {
    yield { type: "started", message: "stub: revalidating" };
    return {
      verdicts: params.batch.flatMap((rec) =>
        rec.findings.map((f) => ({
          filePath: rec.filePath,
          title: f.title,
          verdict: "true-positive",
          reasoning: "stub: confirmed",
        })),
      ),
      meta: {
        durationMs: 1,
        usage: {
          inputTokens: 1,
          outputTokens: 1,
          cacheReadInputTokens: 0,
          cacheCreationInputTokens: 0,
        },
      },
    };
  },
};

export default { name: "stub", agents: [stub] };
`;

function injectStubPlugin(configPath: string): void {
  const original = fs.readFileSync(configPath, "utf-8");
  const patched = original
    .replace(
      'import { defineConfig } from "deepsec/config";\n',
      'import { defineConfig } from "deepsec/config";\nimport stubPlugin from "./stub-plugin.mjs";\n',
    )
    .replace(
      /export default defineConfig\(\{\s*\n\s*projects:/,
      "export default defineConfig({\n  plugins: [stubPlugin],\n  projects:",
    );
  if (patched === original) {
    throw new Error(`failed to patch ${configPath} — template format changed?`);
  }
  fs.writeFileSync(configPath, patched);
}

function runBundle(args: string[], cwd: string, timeoutMs: number, tmp: string) {
  const bundle = path.join(tmp, BUNDLE_REL);
  const r = spawnSync("node", ["--preserve-symlinks-main", bundle, ...args], {
    cwd,
    env: process.env,
    encoding: "utf-8",
    timeout: timeoutMs,
    // Surface live progress so a stuck bootstrap is visible without
    // waiting for the timeout.
    stdio: ["ignore", "inherit", "inherit"],
  });
  return { status: r.status ?? -1 };
}

/**
 * Variant that captures stdout so we can assert on it. Used for the
 * read-only commands (metrics, status) where we want to inspect output;
 * the long-running sandbox commands keep the live-stream form above so
 * the operator can watch progress.
 */
function runBundleCapture(args: string[], cwd: string, timeoutMs: number, tmp: string) {
  const bundle = path.join(tmp, BUNDLE_REL);
  const r = spawnSync("node", ["--preserve-symlinks-main", bundle, ...args], {
    cwd,
    env: process.env,
    encoding: "utf-8",
    timeout: timeoutMs,
  });
  return {
    stdout: r.stdout ?? "",
    stderr: r.stderr ?? "",
    status: r.status ?? -1,
  };
}

/**
 * Truncate a credential to its first 4 chars (or shorter) for log
 * lines. Lets us assert in CI logs that the right secret made it
 * through without leaking the rest. Returns "<unset>" when missing
 * so a typo in secret naming surfaces visibly.
 */
function fingerprint(value: string | undefined): string {
  if (!value) return "<unset>";
  return `${value.slice(0, 4)}…`;
}

/**
 * List `deepsec-tar-*` temp files currently in `os.tmpdir()`. Used as a
 * before/after snapshot around sandbox invocations: makeTarball writes
 * each upload bundle to a path under os.tmpdir(), and either the
 * uploader or the orchestrator's finally block is supposed to unlink
 * the file when the bundle is no longer needed. A leak here would mean
 * a long-running orchestrator slowly fills /tmp — invisible from the
 * unit tests, which only verify a single makeTarball call.
 *
 * We diff before/after rather than asserting an empty set so concurrent
 * CI jobs on the same runner don't cause false positives.
 */
function listDeepsecTarballs(): string[] {
  return fs
    .readdirSync(os.tmpdir())
    .filter((n) => n.startsWith("deepsec-tar-") && n.endsWith(".tar.gz"));
}

/**
 * Pack the local `packages/deepsec` into a `.tgz` tarball — same format
 * `npm publish` would ship. Returns the absolute path to the produced
 * file. Used by the live-sandbox test to substitute the local source
 * for the npm-published `deepsec` dep, so a version bump in HEAD
 * doesn't break the test waiting for npm to catch up.
 */
function packLocalDeepsec(destDir: string): string {
  fs.mkdirSync(destDir, { recursive: true });
  const result = spawnSync("npm", ["pack", "--silent", "--pack-destination", destDir], {
    cwd: path.join(ROOT, "packages/deepsec"),
    encoding: "utf-8",
    timeout: 60_000,
  });
  if (result.status !== 0) {
    throw new Error(
      `npm pack failed (exit ${result.status}):\nstdout: ${result.stdout}\nstderr: ${result.stderr}`,
    );
  }
  // npm pack --silent prints just the filename to stdout, e.g. `deepsec-1.1.7.tgz\n`.
  const filename = result.stdout.trim().split("\n").pop() ?? "";
  if (!filename?.endsWith(".tgz")) {
    throw new Error(`npm pack did not produce a .tgz (stdout: ${JSON.stringify(result.stdout)})`);
  }
  return path.join(destDir, filename);
}

describe.skipIf(!SHOULD_RUN)("pipeline e2e — live sandbox", () => {
  beforeAll(() => {
    const realBundle = path.join(ROOT, "packages/deepsec/dist/cli.mjs");
    if (!fs.existsSync(realBundle)) {
      throw new Error(`Bundle not found at ${realBundle}. Run \`pnpm bundle\` first.`);
    }
    if (LIVE && !HAS_SANDBOX_KEY) {
      console.warn("DEEPSEC_E2E_LIVE_SANDBOX=1 but no Vercel Sandbox key — skipping.");
    }
    // Fingerprint the Vercel creds so CI logs confirm we got the
    // right secrets without exposing them. First 4 chars only.
    console.log(
      `[live-sandbox] creds: teamId=${fingerprint(process.env.VERCEL_TEAM_ID)} ` +
        `projectId=${fingerprint(process.env.VERCEL_PROJECT_ID)} ` +
        `token=${fingerprint(process.env.VERCEL_TOKEN)} ` +
        `oidc=${fingerprint(process.env.VERCEL_OIDC_TOKEN)}`,
    );
  });

  it(
    "init → scan → sandbox process → sandbox revalidate",
    () => {
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-live-"));
      try {
        const workspaceDir = path.join(tmp, ".deepsec");
        fs.symlinkSync(path.join(ROOT, "node_modules"), path.join(tmp, "node_modules"), "dir");

        // 1. init
        const init = runBundle(
          ["init", workspaceDir, FIXTURES, "--id", "fixture"],
          tmp,
          60_000,
          tmp,
        );
        expect(init.status).toBe(0);

        // 2. Substitute the scaffolded `"deepsec": "^x.y.z"` (which
        // points at npm) with a `file:` reference to a tarball of the
        // local source. Otherwise: every version bump in HEAD breaks
        // this test until npm catches up — `pnpm install` inside the
        // sandbox can't resolve a version that hasn't been published
        // yet. With `file:./deepsec-x.y.z.tgz`, the sandbox uses
        // exactly the code in this branch, every run.
        const tarballPath = packLocalDeepsec(workspaceDir);
        const tarballName = path.basename(tarballPath);
        const pkgPath = path.join(workspaceDir, "package.json");
        const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
        pkg.dependencies.deepsec = `file:./${tarballName}`;
        fs.writeFileSync(pkgPath, `${JSON.stringify(pkg, null, 2)}\n`);

        // 3. Drop the stub plugin + register it. Same shape as
        // pipeline.test.ts — the plugin file ships into the sandbox
        // via the `.deepsec/` tarball, so the worker imports it
        // alongside `deepsec.config.ts`.
        fs.writeFileSync(path.join(workspaceDir, "stub-plugin.mjs"), STUB_PLUGIN_SOURCE);
        injectStubPlugin(path.join(workspaceDir, "deepsec.config.ts"));

        fs.symlinkSync(
          path.join(tmp, "node_modules"),
          path.join(workspaceDir, "node_modules"),
          "dir",
        );

        // 3. scan locally
        const scan = runBundle(["scan"], workspaceDir, 60_000, tmp);
        expect(scan.status).toBe(0);

        // 4. sandbox process — 1 sandbox, 2 files, stub agent. The
        // proxy is skipped for non-claude-agent-sdk agents (see
        // setup.ts), so no AI credentials needed. Bootstrap + worker
        // is ~3-5 min — most of that is bootstrap snapshot creation.
        //
        // Snapshot /tmp before/after to verify the disk-backed tarball
        // path cleans up after itself. Each `sandbox process` builds
        // three upload bundles (app + target + data) into os.tmpdir()
        // and is supposed to unlink them after upload completes (the
        // uploader does it on success, the orchestrator's finally
        // block sweeps any survivors). A regression that holds onto
        // those files would slowly fill /tmp on long-running invokers.
        const tarsBeforeProc = listDeepsecTarballs();
        const proc = runBundle(
          [
            "sandbox",
            "process",
            "--sandboxes",
            "1",
            "--vcpus",
            "2",
            "--limit",
            "2",
            "--concurrency",
            "1",
            "--agent",
            "stub",
          ],
          workspaceDir,
          15 * 60_000,
          tmp,
        );
        expect(proc.status).toBe(0);
        const tarsAfterProc = listDeepsecTarballs();
        const leakedProc = tarsAfterProc.filter((n) => !tarsBeforeProc.includes(n));
        expect(
          leakedProc,
          `sandbox process leaked tarballs in os.tmpdir(): ${leakedProc.join(", ")}`,
        ).toEqual([]);

        // Findings should be on disk, populated by the stub agent
        // running INSIDE the sandbox and merged back via the result
        // tarball download.
        const filesDir = path.join(workspaceDir, "data/fixture/files");
        const recs = readAllRecords(filesDir);
        const withFindings = recs.filter((r) => r.findings.length > 0);
        expect(withFindings.length, "process should have produced findings").toBeGreaterThan(0);
        expect(withFindings[0].findings[0].title).toMatch(/^stub finding for /);
        expect(withFindings[0].analysisHistory.some((h) => h.agentType === "stub")).toBe(true);

        // 5. sandbox revalidate over the same findings.
        const tarsBeforeReval = listDeepsecTarballs();
        const reval = runBundle(
          [
            "sandbox",
            "revalidate",
            "--sandboxes",
            "1",
            "--vcpus",
            "2",
            "--limit",
            "2",
            "--concurrency",
            "1",
            "--agent",
            "stub",
          ],
          workspaceDir,
          15 * 60_000,
          tmp,
        );
        expect(reval.status).toBe(0);
        const tarsAfterReval = listDeepsecTarballs();
        const leakedReval = tarsAfterReval.filter((n) => !tarsBeforeReval.includes(n));
        expect(
          leakedReval,
          `sandbox revalidate leaked tarballs in os.tmpdir(): ${leakedReval.join(", ")}`,
        ).toEqual([]);

        const after = readAllRecords(filesDir);
        const verdicts = after.flatMap((r) => r.findings.filter((f) => f.revalidation));
        expect(verdicts.length, "revalidate should have produced verdicts").toBeGreaterThan(0);
        expect(verdicts[0].revalidation?.verdict).toBe("true-positive");

        // 6. Read-only commands. Same set as pipeline.test.ts — confirms
        // the data dir produced by the sandbox path is structurally
        // identical to the local-process path.
        const metrics = runBundleCapture(["metrics"], workspaceDir, 30_000, tmp);
        expect(metrics.status).toBe(0);
        expect(metrics.stdout).toContain("fixture");

        const report = runBundleCapture(["report"], workspaceDir, 30_000, tmp);
        expect(report.status).toBe(0);
        const reportsDir = path.join(workspaceDir, "data/fixture/reports");
        expect(fs.existsSync(path.join(reportsDir, "report.json"))).toBe(true);
        expect(fs.existsSync(path.join(reportsDir, "report.md"))).toBe(true);
        const reportJson = JSON.parse(
          fs.readFileSync(path.join(reportsDir, "report.json"), "utf-8"),
        );
        expect(reportJson.summary.totalFindings).toBeGreaterThan(0);

        const exportPath = path.join(workspaceDir, "exported.json");
        const exportJson = runBundleCapture(
          ["export", "--format", "json", "--out", exportPath],
          workspaceDir,
          30_000,
          tmp,
        );
        expect(exportJson.status).toBe(0);
        const exported = JSON.parse(fs.readFileSync(exportPath, "utf-8"));
        expect(Array.isArray(exported)).toBe(true);
        expect(exported.length).toBeGreaterThan(0);

        const mdDir = path.join(workspaceDir, "exported");
        const exportMd = runBundleCapture(
          ["export", "--format", "md-dir", "--out", mdDir],
          workspaceDir,
          30_000,
          tmp,
        );
        expect(exportMd.status).toBe(0);
        const mdFiles = fs
          .readdirSync(mdDir, { recursive: true })
          .filter((e) => typeof e === "string" && e.endsWith(".md"));
        expect(mdFiles.length).toBeGreaterThan(0);

        const status = runBundleCapture(["status"], workspaceDir, 30_000, tmp);
        expect(status.status).toBe(0);
        expect(status.stdout).toContain("fixture");
      } finally {
        fs.rmSync(tmp, { recursive: true, force: true });
      }
    },
    // Vitest test-level timeout: 35 min covers worst-case bootstrap +
    // both sandbox passes with retries.
    35 * 60_000,
  );
});

interface PersistedRecord {
  filePath: string;
  findings: Array<{
    title: string;
    severity: string;
    revalidation?: { verdict: string; reasoning: string };
  }>;
  analysisHistory: Array<{ agentType: string }>;
}

function readAllRecords(dir: string): PersistedRecord[] {
  const out: PersistedRecord[] = [];
  if (!fs.existsSync(dir)) return out;
  function walk(d: string) {
    for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, entry.name);
      if (entry.isDirectory()) walk(p);
      else if (entry.name.endsWith(".json")) {
        out.push(JSON.parse(fs.readFileSync(p, "utf-8")));
      }
    }
  }
  walk(dir);
  return out;
}

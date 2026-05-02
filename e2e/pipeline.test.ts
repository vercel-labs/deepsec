/**
 * Full-pipeline e2e: init → scan → process → revalidate, all through the
 * bundled CLI, with a stub agent supplied via a plugin in deepsec.config.ts.
 *
 * This is the gap the unit tests + the per-step bundle e2e tests left:
 * `process` and `revalidate` invoked through the published binary, with
 * findings + verdicts persisted to disk and inspected. No network calls,
 * no real model — the stub agent emits canned output so the pipeline is
 * deterministic.
 *
 * For the live-sandbox sibling (real Vercel Sandbox + real model), see
 * `pipeline-sandbox.test.ts` (gated on credentials, opt-in).
 */

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { beforeAll, describe, expect, it } from "vitest";

const ROOT = path.resolve(import.meta.dirname, "..");
const BUNDLE = path.join(ROOT, "packages/deepsec/dist/cli.mjs");
const FIXTURES = path.join(ROOT, "fixtures/vulnerable-app");

interface RunResult {
  stdout: string;
  stderr: string;
  status: number;
}

function runBundle(args: string[], cwd: string): RunResult {
  const result = spawnSync("node", [BUNDLE, ...args], {
    cwd,
    env: process.env,
    encoding: "utf-8",
    timeout: 120_000,
  });
  return {
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    status: result.status ?? -1,
  };
}

function readAllRecords(dir: string): Array<{
  filePath: string;
  findings: Array<{
    title: string;
    severity: string;
    revalidation?: { verdict: string; reasoning: string; runId: string };
  }>;
  analysisHistory: Array<{ agentType: string; runId: string }>;
}> {
  const out: Array<{
    filePath: string;
    findings: Array<{
      title: string;
      severity: string;
      revalidation?: { verdict: string; reasoning: string; runId: string };
    }>;
    analysisHistory: Array<{ agentType: string; runId: string }>;
  }> = [];
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

/**
 * Inline stub-agent plugin. The bundled CLI loads `deepsec.config.ts`
 * via jiti, which can also load `.ts` plugin files referenced from it.
 * We use a `.mjs` here to keep things simple — the plugin only needs
 * default-export of `{ name, agents: [...] }` matching `DeepsecPlugin`.
 *
 * The agent emits one HIGH finding per candidate-bearing file in
 * investigate(), and one true-positive verdict per finding in
 * revalidate(). Mirrors the StubAgent in
 * packages/processor/src/__tests__/stub-agent.ts but rewritten as ESM
 * for the bundled-CLI loader.
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

/**
 * Patch the scaffolded `deepsec.config.ts` so it loads the stub plugin.
 * We splice the import + a `plugins: [stubPlugin]` entry into the existing
 * `defineConfig({ … })` call without disturbing the projects-insert marker
 * (which init-project relies on for future appends).
 */
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

describe("pipeline e2e", () => {
  beforeAll(() => {
    if (!fs.existsSync(BUNDLE)) {
      throw new Error(`Bundle not found at ${BUNDLE}. Run \`pnpm bundle\` first.`);
    }
  });

  it("init → scan → process → revalidate with a stub agent plugin", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-pipeline-"));
    try {
      const workspaceDir = path.join(tmp, ".deepsec");

      // Symlink the source repo's node_modules into both tmp/ and the
      // workspace dir so deepsec.config.ts (which imports
      // `deepsec/config`) and the bundled CLI's jiti loader can resolve
      // the package without a real `pnpm install` round-trip.
      fs.symlinkSync(path.join(ROOT, "node_modules"), path.join(tmp, "node_modules"), "dir");

      // 1. init — scaffolds .deepsec/ with the fixture as the first project
      const init = runBundle(["init", workspaceDir, FIXTURES, "--id", "fixture"], tmp);
      expect(init.status, `init stderr: ${init.stderr}\nstdout: ${init.stdout}`).toBe(0);
      expect(fs.existsSync(path.join(workspaceDir, "deepsec.config.ts"))).toBe(true);
      expect(fs.existsSync(path.join(workspaceDir, "data/fixture/project.json"))).toBe(true);

      // 2. Drop the stub plugin + register it in the config
      fs.writeFileSync(path.join(workspaceDir, "stub-plugin.mjs"), STUB_PLUGIN_SOURCE);
      injectStubPlugin(path.join(workspaceDir, "deepsec.config.ts"));

      // Make node_modules visible from the workspace (jiti resolves
      // `deepsec/config` against the cwd's node_modules).
      fs.symlinkSync(
        path.join(tmp, "node_modules"),
        path.join(workspaceDir, "node_modules"),
        "dir",
      );

      // 3. scan — auto-resolves project-id since there's only one project
      const scan = runBundle(["scan"], workspaceDir);
      expect(scan.status, `scan stderr: ${scan.stderr}\nstdout: ${scan.stdout}`).toBe(0);
      const filesDir = path.join(workspaceDir, "data/fixture/files");
      expect(fs.existsSync(filesDir)).toBe(true);

      // 4. process --agent stub — should pick up the plugin's agent
      const proc = runBundle(["process", "--agent", "stub"], workspaceDir);
      expect(proc.status, `process stderr: ${proc.stderr}\nstdout: ${proc.stdout}`).toBe(0);

      const afterProcess = readAllRecords(filesDir);
      const recsWithFindings = afterProcess.filter((r) => r.findings.length > 0);
      expect(recsWithFindings.length, "process should have produced findings").toBeGreaterThan(0);
      // Stub emits a deterministic title — confirms our plugin actually ran.
      expect(recsWithFindings[0].findings[0].title).toMatch(/^stub finding for /);
      // analysisHistory carries the agentType through end-to-end.
      expect(recsWithFindings[0].analysisHistory.some((h) => h.agentType === "stub")).toBe(true);
      // No verdicts yet — revalidate hasn't run.
      expect(recsWithFindings[0].findings[0].revalidation).toBeUndefined();

      // 5. revalidate --agent stub — should add a true-positive verdict
      // to every finding from step 4.
      const reval = runBundle(["revalidate", "--agent", "stub"], workspaceDir);
      expect(reval.status, `revalidate stderr: ${reval.stderr}\nstdout: ${reval.stdout}`).toBe(0);

      const afterRevalidate = readAllRecords(filesDir);
      const revalidated = afterRevalidate.flatMap((r) => r.findings.filter((f) => f.revalidation));
      expect(revalidated.length, "revalidate should have produced verdicts").toBeGreaterThan(0);
      expect(revalidated[0].revalidation?.verdict).toBe("true-positive");
      expect(revalidated[0].revalidation?.reasoning).toContain("stub");

      // 6. Read-only commands that consume the data dir produced above.
      // These don't go through the agent; they just verify our findings
      // round-trip cleanly through the export/report/metrics surfaces.

      // metrics — text-table summary, prints findings counts + verdict
      // breakdown. We just assert it lists our project + the TP count we
      // know from the stub.
      const metrics = runBundle(["metrics"], workspaceDir);
      expect(metrics.status, `metrics stderr: ${metrics.stderr}`).toBe(0);
      expect(metrics.stdout).toContain("fixture");
      expect(metrics.stdout).toMatch(/HIGH/);
      // Stub returns true-positive for every finding; ensure the TP
      // column reflects that.
      expect(metrics.stdout).toMatch(/True Positives by Vulnerability Type/);

      // report — writes a JSON + Markdown summary under data/<id>/reports/
      const report = runBundle(["report"], workspaceDir);
      expect(report.status, `report stderr: ${report.stderr}`).toBe(0);
      const reportsDir = path.join(workspaceDir, "data/fixture/reports");
      expect(fs.existsSync(path.join(reportsDir, "report.json"))).toBe(true);
      expect(fs.existsSync(path.join(reportsDir, "report.md"))).toBe(true);
      const reportJson = JSON.parse(fs.readFileSync(path.join(reportsDir, "report.json"), "utf-8"));
      expect(reportJson.projectId).toBe("fixture");
      expect(reportJson.summary.totalFindings).toBeGreaterThan(0);
      expect(reportJson.summary.high).toBeGreaterThan(0); // stub emits HIGH
      expect(Array.isArray(reportJson.files)).toBe(true);
      const fileWithFindings = reportJson.files.find(
        (f: { findings: unknown[] }) => f.findings.length > 0,
      );
      expect(fileWithFindings).toBeDefined();

      // export --format json --out <file> — write to a file so stdout
      // banners don't get mixed into the parsed JSON.
      const exportPath = path.join(workspaceDir, "exported.json");
      const exportJson = runBundle(
        ["export", "--format", "json", "--out", exportPath],
        workspaceDir,
      );
      expect(exportJson.status, `export stderr: ${exportJson.stderr}`).toBe(0);
      const exported = JSON.parse(fs.readFileSync(exportPath, "utf-8"));
      expect(Array.isArray(exported)).toBe(true);
      expect(exported.length).toBeGreaterThan(0);
      // True-positive filter — must drop nothing since stub returns
      // true-positive for every finding.
      const exportTpPath = path.join(workspaceDir, "exported-tp.json");
      const exportTp = runBundle(
        ["export", "--format", "json", "--only-true-positive", "--out", exportTpPath],
        workspaceDir,
      );
      expect(exportTp.status).toBe(0);
      expect(JSON.parse(fs.readFileSync(exportTpPath, "utf-8")).length).toBe(exported.length);

      // export --format md-dir — directory of one .md per finding.
      const mdDir = path.join(workspaceDir, "exported");
      const exportMd = runBundle(["export", "--format", "md-dir", "--out", mdDir], workspaceDir);
      expect(exportMd.status, `export-md stderr: ${exportMd.stderr}`).toBe(0);
      expect(fs.existsSync(mdDir)).toBe(true);
      const mdFiles = fs
        .readdirSync(mdDir, { recursive: true })
        .filter((e) => typeof e === "string" && e.endsWith(".md"));
      expect(mdFiles.length).toBeGreaterThan(0);

      // status — prints run history. Should mention both runs.
      const status = runBundle(["status"], workspaceDir);
      expect(status.status, `status stderr: ${status.stderr}`).toBe(0);
      expect(status.stdout).toContain("fixture");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

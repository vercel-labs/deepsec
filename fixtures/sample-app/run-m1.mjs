// Milestone 1 end-to-end runner: starts server.mjs on an ephemeral port,
// builds a security-headers scope for the routes the manifest covers,
// executes it via the M1 executor (loopback no-op approval), and compares
// the verdicts to expectations.json. Requires `pnpm -C packages/core build`.
//
// Run from anywhere: node fixtures/sample-app/run-m1.mjs

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const fixtureDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(fixtureDir, "..", "..");

const coreDist = path.join(repoRoot, "packages", "core", "dist", "index.js");
if (!fs.existsSync(coreDist)) {
  console.error("packages/core is not built. Run: pnpm -C packages/core build");
  process.exit(1);
}
const core = await import(coreDist);

// The executor lives in the deepsec package (TS); import it through tsx.
const tsxCli = path.join(repoRoot, "node_modules", "tsx", "dist", "cli.mjs");
const executeModule = path.join(repoRoot, "packages", "deepsec", "src", "live", "execute.ts");
if (!fs.existsSync(tsxCli)) {
  console.error("tsx is not installed. Run: pnpm install");
  process.exit(1);
}

const TEMPLATE = "security-headers";

function startServer() {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(fixtureDir, "server.mjs"), "0"], {
      stdio: ["ignore", "pipe", "inherit"],
    });
    let buffer = "";
    child.stdout.on("data", (chunk) => {
      buffer += chunk;
      const match = /listening on (http:\/\/127\.0\.0\.1:\d+)/.exec(buffer);
      if (match) resolve({ child, baseUrl: match[1] });
    });
    child.on("error", reject);
    child.on("exit", (code) => reject(new Error(`server exited early (${code}): ${buffer}`)));
  });
}

function buildScope(baseUrl, routes) {
  const scope = {
    projectId: "sample-app",
    targetId: "sample-app-local",
    baseUrl,
    allowedOrigins: [],
    selectedFindingIds: [],
    selectedRoutes: routes.map((route) => ({ routeId: route, templateId: TEMPLATE })),
    allowedMethods: ["GET"],
    allowedPathPrefixes: ["/"],
    identities: [],
    limits: {
      maxRequestsPerUnit: 20,
      maxRequestsPerMinute: 30,
      maxResponseBytes: 1_000_000,
      timeoutMs: 10_000,
    },
    permittedRiskClasses: ["passive"],
    plans: routes.map((route) => ({
      id: `hunt:${route}:${TEMPLATE}`,
      templateId: TEMPLATE,
      route,
      methods: ["GET"],
      identityRef: "anonymous",
      assertions: core.EXPECTED_SECURITY_HEADERS
        ? [...core.EXPECTED_SECURITY_HEADERS].map((h) => `header-present:${h}`)
        : [],
      riskClass: "passive",
      limits: {
        maxRequestsPerUnit: 20,
        maxRequestsPerMinute: 30,
        maxResponseBytes: 1_000_000,
        timeoutMs: 10_000,
      },
    })),
  };
  scope.digest = core.digestScopeManifest(scope);
  return scope;
}

const expectations = JSON.parse(
  fs.readFileSync(path.join(fixtureDir, "expectations.json"), "utf-8"),
);
const routes = expectations.expectations.filter((e) => TEMPLATE in e.templates).map((e) => e.route);

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-m1-"));
process.env.DEEPSEC_DATA_ROOT = dataRoot;

const { child, baseUrl } = await startServer();
console.log(`sample-app: ${baseUrl}`);

try {
  const scope = buildScope(baseUrl, routes);
  const scopePath = path.join(dataRoot, "scope.json");
  fs.writeFileSync(scopePath, JSON.stringify(scope, null, 2) + "\n");

  // Execute through tsx so the TS executor imports cleanly. Args are passed via
  // env (not process.argv) because tsx rewrites argv: the script path lands in
  // argv[1], shifting positional args — an argv-based read is not robust.
  const driver = `
    import { executeLiveScope } from ${JSON.stringify(executeModule)};
    import fs from "node:fs";
    const scope = JSON.parse(fs.readFileSync(process.env.M1_SCOPE_PATH, "utf-8"));
    const { summary, runDir } = await executeLiveScope({
      scope,
      approveDigest: process.env.M1_APPROVE_DIGEST,
    });
    console.log(JSON.stringify({ summary, runDir }));
  `;
  const driverPath = path.join(dataRoot, "driver.mjs");
  fs.writeFileSync(driverPath, driver);

  const out = await new Promise((resolve, reject) => {
    const proc = spawn(process.execPath, [tsxCli, driverPath], {
      env: {
        ...process.env,
        DEEPSEC_DATA_ROOT: dataRoot,
        M1_SCOPE_PATH: scopePath,
        M1_APPROVE_DIGEST: scope.digest,
      },
      stdio: ["ignore", "pipe", "inherit"],
    });
    let buf = "";
    proc.stdout.on("data", (c) => (buf += c));
    proc.on("error", reject);
    proc.on("exit", (code) =>
      code === 0 ? resolve(buf) : reject(new Error(`executor exited ${code}`)),
    );
  });
  const { summary, runDir } = JSON.parse(out.trim().split("\n").pop());

  console.log(`run: ${summary.runId} (${summary.counts.requests} request(s))`);
  const actual = new Map(summary.units.map((u) => [`${u.route} ${u.templateId}`, u.verdict]));
  let failures = 0;
  for (const exp of expectations.expectations) {
    if (!(TEMPLATE in exp.templates)) continue;
    const got = actual.get(`${exp.route} ${TEMPLATE}`);
    const expected = exp.templates[TEMPLATE];
    const ok = got === expected;
    if (!ok) failures++;
    console.log(
      `  ${ok ? "PASS" : "FAIL"} ${exp.route}  expected=${expected}  actual=${got ?? "<missing>"}`,
    );
  }
  console.log(`artifacts: ${runDir}`);
  if (failures > 0) {
    console.error(`${failures} verdict(s) did not match expectations.json`);
    process.exit(1);
  }
  console.log("All verdicts match expectations.json");
} finally {
  child.kill();
}

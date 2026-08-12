import { type ChildProcess, spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { digestScopeManifest, type LiveScopeManifest, type LiveVerdict } from "@deepsec/core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { executeLiveScope } from "../live/execute.js";
import {
  compareWithExpectations,
  loadSampleAppExpectations,
  sampleAppServerPath,
} from "../live/sample-app.js";
import { SECURITY_HEADERS_TEMPLATE_ID } from "../live/templates/security-headers.js";

// ---------------------------------------------------------------------------
// Milestone 1 end-to-end: the real fixture server (started as a child process
// on an ephemeral port), the real executor, and the ground-truth manifest.
// ---------------------------------------------------------------------------

let child: ChildProcess;
let baseUrl = "";
let dataRoot: string;

beforeAll(async () => {
  dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-sample-app-"));
  process.env.DEEPSEC_DATA_ROOT = dataRoot;

  const started = await new Promise<{ child: ChildProcess; baseUrl: string }>((resolve, reject) => {
    const proc = spawn(process.execPath, [sampleAppServerPath(), "0"], {
      stdio: ["ignore", "pipe", "inherit"],
    });
    let buffer = "";
    proc.stdout?.on("data", (chunk) => {
      buffer += chunk;
      const match = /listening on (http:\/\/127\.0\.0\.1:\d+)/.exec(buffer);
      if (match) resolve({ child: proc, baseUrl: match[1] });
    });
    proc.on("error", reject);
    proc.on("exit", (code) => reject(new Error(`sample app exited early (${code})`)));
  });
  child = started.child;
  baseUrl = started.baseUrl;
});

afterAll(() => {
  child.kill();
  fs.rmSync(dataRoot, { recursive: true, force: true });
});

function planFor(route: string) {
  return {
    id: `hunt:${route}:${SECURITY_HEADERS_TEMPLATE_ID}`,
    templateId: SECURITY_HEADERS_TEMPLATE_ID,
    route,
    methods: ["GET" as const],
    identityRef: "anonymous",
    assertions: [],
    riskClass: "passive" as const,
    limits: {
      maxRequestsPerUnit: 20,
      maxRequestsPerMinute: 30,
      maxResponseBytes: 1_000_000,
      timeoutMs: 10_000,
    },
  };
}

describe("sample-app end-to-end (security-headers template)", () => {
  it("produces verdicts matching expectations.json", async () => {
    const expectations = loadSampleAppExpectations();
    const routes = expectations.expectations
      .filter((e) => SECURITY_HEADERS_TEMPLATE_ID in e.templates)
      .map((e) => e.route);
    expect(routes).toContain("/api/weak-headers");
    expect(routes).toContain("/api/secure");

    const scope: LiveScopeManifest = {
      projectId: "sample-app",
      targetId: "sample-app-local",
      baseUrl,
      allowedOrigins: [],
      selectedFindingIds: [],
      selectedRoutes: routes.map((routeId) => ({
        routeId,
        templateId: SECURITY_HEADERS_TEMPLATE_ID,
      })),
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
      plans: routes.map(planFor),
    };
    scope.digest = digestScopeManifest(scope);

    // Loopback: approval is a no-op, so passing the digest is optional but
    // harmless; the one-command loop is exercised here.
    const { summary } = await executeLiveScope({
      scope,
      approveDigest: scope.digest,
      runId: "sample-app-e2e",
    });

    const actual = new Map<string, LiveVerdict>(
      summary.units.map((u) => [`${u.route} ${u.templateId}`, u.verdict ?? "inconclusive"]),
    );
    expect(actual.get("/api/weak-headers security-headers")).toBe("confirmed");
    expect(actual.get("/api/secure security-headers")).toBe("not-observed");

    const comparisons = compareWithExpectations(expectations, actual);
    expect(comparisons.length).toBeGreaterThan(0);
    for (const c of comparisons) {
      expect(c.match, `${c.route} ${c.template}: expected ${c.expected}, got ${c.actual}`).toBe(
        true,
      );
    }

    // Every unit executed, nothing blocked, and artifacts were written.
    expect(summary.counts.blocked).toBe(0);
    expect(summary.counts.executed).toBe(routes.length);
    expect(summary.loopbackApproval).toBe(true);
    for (const unit of summary.units) {
      expect(unit.evidenceRef).toBeDefined();
    }
  });
});

import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import {
  digestScopeManifest,
  type LiveEvidence,
  type LiveScopeManifest,
  liveBlockersPath,
  liveEvidenceDir,
  liveRunSummaryPath,
} from "@deepsec/core";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  executeLiveScope,
  isLoopbackScope,
  ScopeRefusal,
  verifyScopeApproval,
} from "../live/execute.js";
import { evidenceIsSanitized, PolicyViolation, ProbeRunner } from "../live/probe.js";
import { adjudicateSecurityHeaders } from "../live/templates/security-headers.js";

// ---------------------------------------------------------------------------
// Milestone 1 tests: the load-bearing invariant end to end.
// typed plan -> policy check -> probe -> typed assertion -> evidence artifact.
// ---------------------------------------------------------------------------

const SECRET_TOKEN = "token-user-a";
const BIG_BODY_BYTES = 4096;

let server: http.Server;
let baseUrl = "";

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    const send = (status: number, body: string, headers: Record<string, string> = {}) => {
      res.writeHead(status, { "content-type": "application/json", ...headers });
      res.end(body);
    };
    switch (url.pathname) {
      case "/secure":
        return send(200, "{}", {
          "x-content-type-options": "nosniff",
          "x-frame-options": "DENY",
          "content-security-policy": "default-src 'none'",
          "strict-transport-security": "max-age=63072000",
        });
      case "/weak":
        return send(200, `{"secret":"${SECRET_TOKEN}"}`);
      case "/redirect":
        return send(302, "", { location: "/weak" });
      case "/redirect-external":
        return send(302, "", { location: "http://169.254.169.254/latest/meta-data" });
      case "/big":
        return send(200, "x".repeat(BIG_BODY_BYTES));
      case "/echo-secret":
        return send(200, "ok", { "x-echo": SECRET_TOKEN });
      default:
        return send(404, "{}");
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  if (addr === null || typeof addr === "string") throw new Error("no address");
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
});

function makeScope(overrides: Partial<LiveScopeManifest> = {}): LiveScopeManifest {
  const plan = {
    id: "hunt:/weak:security-headers",
    templateId: "security-headers",
    route: "/weak",
    methods: ["GET" as const],
    identityRef: "anonymous",
    assertions: [],
    riskClass: "passive" as const,
    limits: {
      maxRequestsPerUnit: 20,
      maxRequestsPerMinute: 30,
      maxResponseBytes: 1_000_000,
      timeoutMs: 5_000,
    },
  };
  const scope: LiveScopeManifest = {
    projectId: "test-live",
    targetId: "loopback",
    baseUrl,
    allowedOrigins: [],
    selectedFindingIds: [],
    selectedRoutes: [],
    allowedMethods: ["GET"],
    allowedPathPrefixes: ["/"],
    identities: [],
    limits: {
      maxRequestsPerUnit: 20,
      maxRequestsPerMinute: 30,
      maxResponseBytes: 1_000_000,
      timeoutMs: 5_000,
    },
    permittedRiskClasses: ["passive"],
    plans: [plan],
    ...overrides,
  };
  scope.digest = digestScopeManifest(scope);
  return scope;
}

let dataRoot: string;
beforeEach(() => {
  dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-live-test-"));
  process.env.DEEPSEC_DATA_ROOT = dataRoot;
});
afterEach(() => {
  fs.rmSync(dataRoot, { recursive: true, force: true });
});

describe("probe runner: exact-origin egress", () => {
  it("rejects non-allowlisted origins", () => {
    const runner = new ProbeRunner({ scope: makeScope() });
    expect(() =>
      runner.check({ unitRef: "u", method: "GET", path: "http://example.com/", purpose: "t" }, 0),
    ).toThrow(PolicyViolation);
  });

  it("rejects http downgrade of an https-allowlisted origin", () => {
    // The approved origin is https; the same host+port over http must not
    // pass the exact-origin check (scheme is part of the origin).
    const scope = makeScope({ baseUrl: "https://127.0.0.1:9999" });
    const runner = new ProbeRunner({ scope });
    expect(() =>
      runner.check(
        { unitRef: "u", method: "GET", path: "http://127.0.0.1:9999/weak", purpose: "t" },
        0,
      ),
    ).toThrow(PolicyViolation);
  });

  it("rejects non-loopback plain-http origins unless explicitly allowlisted", () => {
    const runner = new ProbeRunner({ scope: makeScope() });
    expect(() =>
      runner.check(
        { unitRef: "u", method: "GET", path: "http://203.0.113.10/api", purpose: "t" },
        0,
      ),
    ).toThrow(PolicyViolation);
  });

  it("rejects ports that do not match the approved origin", () => {
    const runner = new ProbeRunner({ scope: makeScope() });
    const otherPort = new URL(baseUrl);
    otherPort.port = String(Number(otherPort.port) + 1);
    expect(() =>
      runner.check(
        { unitRef: "u", method: "GET", path: `${otherPort.origin}/weak`, purpose: "t" },
        0,
      ),
    ).toThrow(PolicyViolation);
  });

  it("rejects credentials embedded in the URL", () => {
    const runner = new ProbeRunner({ scope: makeScope() });
    const withCreds = new URL(baseUrl);
    withCreds.username = "u";
    withCreds.password = "p";
    expect(() =>
      runner.check(
        {
          unitRef: "u",
          method: "GET",
          path: `${withCreds.origin}/weak`.replace("://", "://u:p@"),
          purpose: "t",
        },
        0,
      ),
    ).toThrow(PolicyViolation);
  });

  it("rejects methods outside the scope", () => {
    const runner = new ProbeRunner({ scope: makeScope() });
    expect(() =>
      runner.check({ unitRef: "u", method: "POST", path: "/weak", purpose: "t" }, 0),
    ).toThrow(/Method POST is not in the approved scope/);
  });

  it("rejects paths outside the approved prefixes", () => {
    const runner = new ProbeRunner({
      scope: makeScope({ allowedPathPrefixes: ["/api/"] }),
    });
    expect(() =>
      runner.check({ unitRef: "u", method: "GET", path: "/weak", purpose: "t" }, 0),
    ).toThrow(/outside the approved prefixes/);
  });
});

describe("probe runner: redirects, budgets, caps", () => {
  it("never follows redirects and records the Location header as data", async () => {
    const scope = makeScope();
    scope.plans[0] = { ...scope.plans[0], route: "/redirect" };
    const runner = new ProbeRunner({ scope });
    const obs = await runner.request(
      { unitRef: "u", method: "GET", path: "/redirect", purpose: "t" },
      0,
    );
    expect(obs.status).toBe(302);
    expect(obs.redirect?.location).toBe("/weak");
    expect(obs.redirect?.locationInScope).toBe(true);
  });

  it("records external redirect targets as out-of-scope data (never requested)", async () => {
    const runner = new ProbeRunner({ scope: makeScope() });
    const obs = await runner.request(
      { unitRef: "u", method: "GET", path: "/redirect-external", purpose: "t" },
      0,
    );
    expect(obs.status).toBe(302);
    expect(obs.redirect?.locationOrigin).toBe("http://169.254.169.254");
    expect(obs.redirect?.locationInScope).toBe(false);
  });

  it("enforces the per-unit request budget", async () => {
    const scope = makeScope();
    scope.limits = { ...scope.limits, maxRequestsPerUnit: 1 };
    const runner = new ProbeRunner({ scope });
    await runner.request({ unitRef: "u", method: "GET", path: "/secure", purpose: "t" }, 0);
    await expect(
      runner.request({ unitRef: "u", method: "GET", path: "/secure", purpose: "t" }, 1),
    ).rejects.toThrow(/exhausted its request budget/);
  });

  it("enforces the per-minute rate cap", async () => {
    const scope = makeScope();
    scope.limits = { ...scope.limits, maxRequestsPerMinute: 1 };
    const runner = new ProbeRunner({ scope });
    await runner.request({ unitRef: "u", method: "GET", path: "/secure", purpose: "t" }, 0);
    await expect(
      runner.request({ unitRef: "v", method: "GET", path: "/secure", purpose: "t" }, 0),
    ).rejects.toThrow(/Rate limit/);
  });

  it("caps response bytes and records truncation, never the body", async () => {
    const scope = makeScope();
    scope.limits = { ...scope.limits, maxResponseBytes: 100 };
    const runner = new ProbeRunner({ scope });
    const obs = await runner.request(
      { unitRef: "u", method: "GET", path: "/big", purpose: "t" },
      0,
    );
    expect(obs.bodyTruncated).toBe(true);
    expect(obs.bodyBytes).toBe(BIG_BODY_BYTES);
    expect(obs.bodyHash).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(obs)).not.toContain("x".repeat(200));
  });
});

describe("redaction", () => {
  it("never persists Authorization values or response bodies in evidence", async () => {
    const scope = makeScope();
    scope.plans[0] = {
      ...scope.plans[0],
      headers: { authorization: `Bearer ${SECRET_TOKEN}` },
    };
    const { summary } = await executeLiveScope({
      scope,
      approveDigest: scope.digest,
      runId: "redaction-run",
      secrets: [SECRET_TOKEN],
    });

    const evidencePath = path.join(
      liveEvidenceDir("test-live", "redaction-run"),
      summary.units[0].evidenceRef!,
    );
    const evidenceRaw = fs.readFileSync(evidencePath, "utf-8");
    expect(evidenceRaw).not.toContain(SECRET_TOKEN);
    expect(evidenceRaw).not.toContain('"authorization":"Bearer');
    expect(evidenceRaw).toContain("[redacted]");

    const evidence = JSON.parse(evidenceRaw) as LiveEvidence;
    expect(evidenceIsSanitized(evidence, [SECRET_TOKEN])).toBe(true);
    // The request record carries only allowlisted header names + redacted values.
    expect(evidence.observations[0].request.headerValues.authorization).toBe("[redacted]");

    // The run directory as a whole must not contain the secret either.
    const auditRaw = fs.readFileSync(
      path.join(dataRoot, "test-live", "live", "redaction-run", "audit.jsonl"),
      "utf-8",
    );
    expect(auditRaw).not.toContain(SECRET_TOKEN);
  });
});

describe("scope approval", () => {
  it("refuses a mismatched digest (non-loopback)", () => {
    const scope = makeScope({ baseUrl: "https://staging.example.test" });
    expect(() => verifyScopeApproval(scope, "0".repeat(64))).toThrow(ScopeRefusal);
    expect(() => verifyScopeApproval(scope, undefined)).toThrow(ScopeRefusal);
    expect(verifyScopeApproval(scope, digestScopeManifest(scope))).toBe(scope.digest);
  });

  it("refuses an expired scope even on loopback", () => {
    const scope = makeScope({ expiresAt: new Date(Date.now() - 1_000).toISOString() });
    expect(() => verifyScopeApproval(scope, scope.digest)).toThrow(/expired/);
  });

  it("treats loopback approval as a no-op", () => {
    const scope = makeScope();
    expect(isLoopbackScope(scope)).toBe(true);
    // No digest, wrong digest — both fine on loopback.
    expect(verifyScopeApproval(scope)).toBe(scope.digest);
    expect(verifyScopeApproval(scope, "bogus")).toBe(scope.digest);
  });
});

describe("execution: blockers and artifacts", () => {
  it("completes a policy-blocked unit as blocked (not failed) with a blocker", async () => {
    const scope = makeScope();
    scope.plans[0] = { ...scope.plans[0], route: "/weak", methods: ["POST"] };
    scope.allowedMethods = ["GET"]; // POST not approved -> the plan's POST is blocked
    scope.plans[0] = {
      ...scope.plans[0],
      id: "hunt:/weak:security-headers",
    };
    // Make the plan actually attempt a blocked method: the template always
    // GETs, so instead block via path prefix.
    scope.allowedPathPrefixes = ["/api/"];
    scope.digest = digestScopeManifest(scope);

    const { summary } = await executeLiveScope({
      scope,
      approveDigest: scope.digest,
      runId: "blocked-run",
    });
    expect(summary.units[0].status).toBe("blocked");
    expect(summary.units[0].verdict).toBe("blocked");
    expect(summary.units[0].blocker?.kind).toBe("scope-expansion");
    expect(summary.blockers).toHaveLength(1);
    expect(summary.counts.blocked).toBe(1);

    const blockers = JSON.parse(
      fs.readFileSync(liveBlockersPath("test-live", "blocked-run"), "utf-8"),
    );
    expect(blockers).toHaveLength(1);
  });

  it("writes append-only evidence, audit log, and run summary", async () => {
    const scope = makeScope();
    const { summary, runDir } = await executeLiveScope({
      scope,
      approveDigest: scope.digest,
      runId: "artifact-run",
    });

    expect(fs.existsSync(liveRunSummaryPath("test-live", "artifact-run"))).toBe(true);
    const auditLines = fs
      .readFileSync(path.join(runDir, "audit.jsonl"), "utf-8")
      .trim()
      .split("\n");
    const events = auditLines.map((l) => JSON.parse(l).event);
    expect(events).toContain("run-started");
    expect(events).toContain("scope-approved");
    expect(events).toContain("action-executed");
    expect(events).toContain("unit-completed");
    expect(events).toContain("run-completed");
    expect(summary.scopeDigest).toBe(scope.digest);
  });
});

describe("security-headers template", () => {
  it("is confirmed when expected headers are missing, not-observed when present", async () => {
    const runnerWeak = new ProbeRunner({ scope: makeScope() });
    const weakObs = await runnerWeak.request(
      { unitRef: "u", method: "GET", path: "/weak", purpose: "t" },
      0,
    );
    const weak = adjudicateSecurityHeaders(weakObs);
    expect(weak.verdict).toBe("confirmed");
    expect(weak.assertions.every((a) => a.outcome === "fail")).toBe(true);

    const runnerSecure = new ProbeRunner({ scope: makeScope() });
    const secureObs = await runnerSecure.request(
      { unitRef: "u", method: "GET", path: "/secure", purpose: "t" },
      0,
    );
    const secure = adjudicateSecurityHeaders(secureObs);
    expect(secure.verdict).toBe("not-observed");
    expect(secure.assertions.every((a) => a.outcome === "pass")).toBe(true);
  });
});

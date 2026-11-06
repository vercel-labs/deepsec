import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ensureProject, fileRecordPath, type Severity, writeFileRecord } from "@deepsec/core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { type ExportedFinding, exportCommand } from "../commands/export.js";
import { repoPathPrefix, toSarif } from "../commands/sarif.js";

function finding(
  severity: Severity = "HIGH",
  metadata: Partial<ExportedFinding["metadata"]> = {},
): ExportedFinding {
  return {
    title: `[${severity}] SQL injection`,
    description: "Untrusted input reaches a database query.",
    severity,
    labels: ["security", "slug:sql-injection"],
    metadata: {
      findingId: "finding_0123456789abcdef",
      projectId: "web",
      filePath: "src/user search.ts",
      lineNumbers: [15, 12, 15],
      severity,
      vulnSlug: "sql-injection",
      confidence: "high",
      discoveredAt: "2026-07-18T12:00:00.000Z",
      runId: "run-1",
      owners: {
        teams: [],
        oncall: [],
        managers: [],
        contributors: [],
        recentCommitters: [],
      },
      ...metadata,
    },
  };
}

describe("toSarif", () => {
  it("emits SARIF 2.1.0 rules, results, and source locations", () => {
    const sarif = toSarif([finding()], "2.2.3");
    const run = sarif.runs[0];

    expect(sarif.version).toBe("2.1.0");
    expect(run.tool.driver).toMatchObject({ name: "deepsec", semanticVersion: "2.2.3" });
    expect(run.tool.driver.rules).toEqual([
      {
        id: "sql-injection/high",
        shortDescription: { text: "sql-injection (HIGH)" },
        defaultConfiguration: { level: "error" },
        properties: { tags: ["security"], "security-severity": "8.0", "deepsec/severity": "HIGH" },
      },
    ]);
    expect(run.results[0]).toMatchObject({
      ruleId: "sql-injection/high",
      ruleIndex: 0,
      level: "error",
      message: { text: "SQL injection" },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: "src/user%20search.ts" },
            region: { startLine: 12 },
          },
        },
      ],
      relatedLocations: [
        {
          id: 1,
          physicalLocation: {
            artifactLocation: { uri: "src/user%20search.ts" },
            region: { startLine: 15 },
          },
        },
      ],
      partialFingerprints: { "deepsecFindingId/v1": "finding_0123456789abcdef" },
      properties: { tags: ["security", "slug:sql-injection"] },
    });
  });

  it("ranks each finding by its own severity, independent of input order", () => {
    const findings = [
      finding("MEDIUM"),
      finding("LOW", { vulnSlug: "command-injection" }),
      finding("CRITICAL"),
      finding("MEDIUM", { filePath: "src/other.ts" }),
    ];
    const run = toSarif(findings, "2.2.3").runs[0];

    expect(run.tool.driver.rules.map((r) => [r.id, r.properties["security-severity"]])).toEqual([
      ["command-injection/low", "2.0"],
      ["sql-injection/critical", "9.5"],
      ["sql-injection/medium", "5.0"],
    ]);
    expect(run.results.map((r) => [r.ruleId, r.ruleIndex])).toEqual([
      ["sql-injection/medium", 2],
      ["command-injection/low", 0],
      ["sql-injection/critical", 1],
      ["sql-injection/medium", 2],
    ]);
    expect(toSarif([...findings].reverse(), "2.2.3").runs[0].tool.driver.rules).toEqual(
      run.tool.driver.rules,
    );
  });

  it("prefixes file paths with the project's path in its repository", () => {
    const result = toSarif([finding()], "2.2.3", "apps/web/").runs[0].results[0];

    expect(result.locations[0].physicalLocation.artifactLocation.uri).toBe(
      "apps/web/src/user%20search.ts",
    );
    expect(result.relatedLocations?.[0].physicalLocation.artifactLocation.uri).toBe(
      "apps/web/src/user%20search.ts",
    );
  });

  it.each([
    ["HIGH_BUG", "warning", { tags: ["correctness"], "problem.severity": "error" }],
    ["BUG", "warning", { tags: ["correctness"], "problem.severity": "warning" }],
    ["LOW", "note", { tags: ["security"], "security-severity": "2.0" }],
  ] as const)("maps %s to level %s and GitHub rule metadata", (severity, level, properties) => {
    const run = toSarif([finding(severity)], "2.2.3").runs[0];

    expect(run.results[0].level).toBe(level);
    expect(run.results[0].properties.tags[0]).toBe(properties.tags[0]);
    expect(run.tool.driver.rules[0].properties).toMatchObject(properties);
  });

  it("omits regions when a finding has no usable line numbers", () => {
    const result = toSarif([finding("HIGH", { lineNumbers: [0] })], "2.2.3").runs[0].results[0];

    expect(result.locations[0].physicalLocation).toEqual({
      artifactLocation: { uri: "src/user%20search.ts" },
    });
    expect(result).not.toHaveProperty("relatedLocations");
  });

  it("rejects multi-project SARIF exports", async () => {
    await expect(
      exportCommand({ format: "sarif", out: "findings.sarif", projectId: "web,api" }),
    ).rejects.toThrow("--format sarif requires exactly one project");
  });
});

describe("repoPathPrefix", () => {
  it("returns the project root's path relative to the git repository root", () => {
    const repo = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-sarif-repo-"));
    try {
      fs.mkdirSync(path.join(repo, "apps/web"), { recursive: true });
      expect(repoPathPrefix(repo)).toBe("");
      execFileSync("git", ["init", "-q"], { cwd: repo });
      expect(repoPathPrefix(repo)).toBe("");
      expect(repoPathPrefix(path.join(repo, "apps/web"))).toBe("apps/web/");
      expect(repoPathPrefix(path.join(repo, "missing"))).toBe("");
    } finally {
      fs.rmSync(repo, { recursive: true, force: true });
    }
  });
});

describe("exportCommand --format sarif", () => {
  let tmp: string;

  afterEach(() => {
    vi.restoreAllMocks();
    delete process.env.DEEPSEC_DATA_ROOT;
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  function setupProject(): string {
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.spyOn(console, "warn").mockImplementation(() => {});
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-sarif-"));
    process.env.DEEPSEC_DATA_ROOT = path.join(tmp, "data");
    const root = path.join(tmp, "repo/apps/web");
    fs.mkdirSync(root, { recursive: true });
    execFileSync("git", ["init", "-q"], { cwd: path.join(tmp, "repo") });
    ensureProject("web", root);
    writeFileRecord({
      filePath: "src/a.ts",
      projectId: "web",
      candidates: [],
      lastScannedAt: "2026-07-18T12:00:00.000Z",
      lastScannedRunId: "run-1",
      fileHash: "x",
      findings: [
        {
          severity: "HIGH",
          vulnSlug: "sql-injection",
          title: "Concatenated query",
          description: "User input reaches a SQL query.",
          lineNumbers: [12],
          recommendation: "Use parameterized queries.",
          confidence: "high",
        },
      ],
      analysisHistory: [
        {
          runId: "run-1",
          investigatedAt: "2026-07-18T12:00:00.000Z",
          durationMs: 1,
          agentType: "claude-agent-sdk",
          model: "m",
          modelConfig: {},
          findingCount: 1,
        },
      ],
      gitInfo: {
        enrichedAt: "2026-07-18T12:00:00.000Z",
        recentCommitters: [{ name: "Rae", email: "rae@example.com", date: "2026-07-01" }],
        ownership: {
          fetchedAt: "2026-07-18T12:00:00.000Z",
          approvers: [],
          contributors: [
            {
              name: "Cy",
              email: "cy@example.com",
              github_username: "cy-gh",
              score: 1,
              context: "",
              last_contrib: "",
            },
          ],
          escalationTeams: [
            {
              name: "Payments",
              slug: "payments-team",
              source: "",
              escalation_path_id: "",
              slack_channel_id: null,
              manager: { email: "mgr@example.com", slack_user_id: "U1" },
              current_oncall: {
                name: "Ona",
                email: "ona@example.com",
                slack_user_id: "U2",
                github_username: "ona-gh",
              },
            },
          ],
        },
      },
      status: "analyzed",
    });
    return path.join(tmp, "findings.sarif");
  }

  it("writes repository-relative paths and no ownership data", async () => {
    const out = setupProject();
    const jsonOut = path.join(tmp, "findings.json");
    await exportCommand({ format: "json", out: jsonOut, projectId: "web" });
    await exportCommand({ format: "sarif", out, projectId: "web" });

    const owners = /@example\.com|cy-gh|ona-gh|payments-team|missing-owner|assignee/;
    expect(fs.readFileSync(jsonOut, "utf-8")).toMatch(owners);
    const sarif = fs.readFileSync(out, "utf-8");
    expect(sarif).not.toMatch(owners);
    const result = JSON.parse(sarif).runs[0].results[0];
    expect(result.locations[0].physicalLocation.artifactLocation.uri).toBe("apps/web/src/a.ts");
    expect(result.message.markdown).toContain("Use parameterized queries.");
  });

  it("fails without writing when a file record is unreadable", async () => {
    const out = setupProject();
    fs.writeFileSync(fileRecordPath("web", "src/b.ts"), '{"filePath": "src/b.ts", "find');

    await expect(exportCommand({ format: "sarif", out, projectId: "web" })).rejects.toThrow(
      /unreadable file record .*b\.ts\.json.*export again after it finishes/,
    );
    expect(fs.existsSync(out)).toBe(false);
  });
});

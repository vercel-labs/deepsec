import type { FileRecord, Finding } from "@deepsec/core";
import { describe, expect, it } from "vitest";
import { runRevalidateIdRepairLoop } from "../agents/shared.js";
import type { RevalidateVerdict } from "../agents/types.js";
import {
  type ExpectedFinding,
  normalizePath,
  normalizeTitle,
  reconcileVerdicts,
  resolveDuplicateRef,
} from "../reconcile.js";

function exp(findingId: string, filePath: string, title: string): ExpectedFinding {
  return { findingId, filePath, title };
}

function verdict(v: Partial<RevalidateVerdict>): RevalidateVerdict {
  return { verdict: "true-positive", reasoning: "r", ...v };
}

describe("normalizeTitle / normalizePath", () => {
  it("collapses whitespace, strips markdown quoting, casefolds, trims punctuation", () => {
    expect(normalizeTitle("  `SQL   Injection` in *login*!  ")).toBe("sql injection in login");
    expect(normalizeTitle("SQL Injection")).toBe(normalizeTitle("sql injection")); // case
    expect(normalizeTitle("“Smart quotes”")).toBe("smart quotes");
  });

  it("applies Unicode normalization (NFKC)", () => {
    expect(normalizeTitle("ﬁle upload")).toBe("file upload");
  });

  it("normalizes path separators and leading ./", () => {
    expect(normalizePath("./src/app.ts")).toBe("src/app.ts");
    expect(normalizePath("src\\app.ts")).toBe("src/app.ts");
  });
});

describe("reconcileVerdicts", () => {
  const expected = [
    exp("finding_aaa", "src/a.ts", "Missing auth on /admin"),
    exp("finding_bbb", "src/a.ts", "SQL injection in search"),
    exp("finding_ccc", "src/b.ts", "Open redirect"),
  ];

  it("matches by exact findingId regardless of title/path noise", () => {
    const res = reconcileVerdicts(expected, [
      verdict({ findingId: "finding_bbb", title: "completely rewritten title" }),
    ]);
    expect(res.matches).toHaveLength(1);
    expect(res.matches[0].expected.findingId).toBe("finding_bbb");
    expect(res.matches[0].diagnostic.matchedBy).toBe("finding-id");
    expect(res.missing.map((e) => e.findingId)).toEqual(["finding_aaa", "finding_ccc"]);
    expect(res.unknown).toHaveLength(0);
  });

  it("matches legacy exact (filePath, title) responses without findingId", () => {
    const res = reconcileVerdicts(expected, [
      verdict({ filePath: "src/a.ts", title: "Missing auth on /admin" }),
    ]);
    expect(res.matches[0].expected.findingId).toBe("finding_aaa");
    expect(res.matches[0].diagnostic.matchedBy).toBe("exact-title");
  });

  it("matches whitespace/case/markdown-mangled titles within the exact file", () => {
    const res = reconcileVerdicts(expected, [
      verdict({ filePath: "./src\\a.ts", title: "  `missing  AUTH` on /admin.  " }),
    ]);
    expect(res.matches[0].expected.findingId).toBe("finding_aaa");
    expect(res.matches[0].diagnostic.matchedBy).toBe("normalized-title");
  });

  it("prefers a valid findingId over an incorrect title", () => {
    const res = reconcileVerdicts(expected, [
      verdict({ findingId: "finding_ccc", filePath: "src/a.ts", title: "totally wrong" }),
    ]);
    expect(res.matches[0].expected.findingId).toBe("finding_ccc");
    expect(res.matches[0].diagnostic.matchedBy).toBe("finding-id");
  });

  it("recovers a unique 1:1 remainder", () => {
    const res = reconcileVerdicts(expected, [
      verdict({ findingId: "finding_aaa" }),
      verdict({ findingId: "finding_bbb" }),
      verdict({ title: "some paraphrased redirect thing" }),
    ]);
    expect(res.matches).toHaveLength(3);
    const remainder = res.matches.find((m) => m.expected.findingId === "finding_ccc");
    expect(remainder?.diagnostic.matchedBy).toBe("unique-remainder");
    expect(res.missing).toHaveLength(0);
  });

  it("does NOT unique-remainder-match when more than one finding remains", () => {
    const res = reconcileVerdicts(expected, [verdict({ title: "who knows" })]);
    expect(res.matches).toHaveLength(0);
    expect(res.missing).toHaveLength(3);
    expect(res.unknown).toHaveLength(1);
  });

  it("marks a verdict ambiguous when normalization matches multiple findings and never guesses", () => {
    const ambExpected = [
      exp("finding_x", "src/a.ts", "SQL Injection"),
      exp("finding_y", "src/a.ts", "sql injection"),
      exp("finding_z", "src/a.ts", "other thing"),
    ];
    const res = reconcileVerdicts(ambExpected, [
      verdict({ filePath: "src/a.ts", title: "SQL INJECTION!" }),
    ]);
    expect(res.matches).toHaveLength(0);
    expect(res.ambiguous).toHaveLength(1);
    expect(res.missing).toHaveLength(3);
  });

  it("gives each finding at most one verdict (first match wins)", () => {
    const res = reconcileVerdicts(expected, [
      verdict({ findingId: "finding_aaa", verdict: "true-positive" }),
      verdict({ findingId: "finding_aaa", verdict: "false-positive" }),
    ]);
    expect(res.matches).toHaveLength(1);
    expect(res.matches[0].verdict.verdict).toBe("true-positive");
  });
});

describe("resolveDuplicateRef", () => {
  const mk = (filePath: string, findings: Array<Partial<Finding> & { title: string }>) =>
    ({
      filePath,
      projectId: "p",
      candidates: [],
      lastScannedAt: "",
      lastScannedRunId: "",
      fileHash: "",
      findings: findings.map((f) => ({
        severity: "HIGH",
        vulnSlug: "s",
        description: "d",
        lineNumbers: [1],
        recommendation: "r",
        confidence: "high",
        ...f,
      })),
      analysisHistory: [],
      status: "analyzed",
    }) as FileRecord;

  it("resolves by findingId, exact title, then normalized title", () => {
    const file = mk("a.ts", [{ title: "Primary Thing", findingId: "finding_p" }]);
    expect(resolveDuplicateRef({ ref: "finding_p", file })?.finding.title).toBe("Primary Thing");
    expect(resolveDuplicateRef({ ref: "Primary Thing", file })?.finding.title).toBe(
      "Primary Thing",
    );
    expect(resolveDuplicateRef({ ref: "`primary thing`", file })?.finding.title).toBe(
      "Primary Thing",
    );
    expect(resolveDuplicateRef({ ref: "nope", file })).toBeUndefined();
  });

  it("returns undefined on ambiguous title references", () => {
    const file = mk("a.ts", [
      { title: "Same Title", findingId: "finding_1" },
      { title: "same title", findingId: "finding_2" },
    ]);
    expect(resolveDuplicateRef({ ref: "SAME TITLE", file })).toBeUndefined();
  });

  it("only crosses files when crossFile is enabled", () => {
    const a = mk("a.ts", [{ title: "dupe", findingId: "finding_d" }]);
    const b = mk("b.ts", [{ title: "the primary", findingId: "finding_p" }]);
    expect(resolveDuplicateRef({ ref: "finding_p", file: a, batch: [a, b] })).toBeUndefined();
    expect(
      resolveDuplicateRef({ ref: "finding_p", file: a, batch: [a, b], crossFile: true })?.finding
        .findingId,
    ).toBe("finding_p");
  });
});

async function drain<T>(gen: AsyncGenerator<unknown, T>): Promise<T> {
  let r = await gen.next();
  while (!r.done) r = await gen.next();
  return r.value;
}

describe("runRevalidateIdRepairLoop", () => {
  const expected = [
    exp("finding_aaa", "a.ts", "one"),
    exp("finding_bbb", "a.ts", "two"),
    exp("finding_ccc", "b.ts", "three"),
  ];

  it("skips repair entirely when everything reconciled", async () => {
    let followUps = 0;
    const out = await drain(
      runRevalidateIdRepairLoop({
        expected,
        verdicts: expected.map((e) => verdict({ findingId: e.findingId })),
        initialRawText: "[]",
        followUp: async () => {
          followUps++;
          return "[]";
        },
        agentLabel: "test",
      }),
    );
    expect(followUps).toBe(0);
    expect(out.repairAttempts).toBe(0);
    expect(out.verdicts).toHaveLength(3);
  });

  it("requests only the missing findings and merges the repair response", async () => {
    const prompts: string[] = [];
    const out = await drain(
      runRevalidateIdRepairLoop({
        expected,
        verdicts: [
          verdict({ findingId: "finding_aaa" }),
          verdict({ findingId: "item_zzz", title: "mangled" }), // unknown identifier
        ],
        initialRawText: "raw-initial",
        followUp: async (p) => {
          prompts.push(p);
          return JSON.stringify([
            { findingId: "finding_bbb", verdict: "false-positive", reasoning: "fp" },
            { findingId: "finding_ccc", verdict: "fixed", reasoning: "gone" },
          ]);
        },
        agentLabel: "test",
      }),
    );
    expect(out.repairAttempts).toBe(1);
    expect(prompts).toHaveLength(1);
    // Repair prompt lists exactly the missing IDs and the unmatched identifier.
    expect(prompts[0]).toContain("finding_bbb");
    expect(prompts[0]).toContain("finding_ccc");
    expect(prompts[0]).not.toMatch(/- finding_aaa —/);
    expect(prompts[0]).toContain("item_zzz");
    // Merged verdicts now reconcile completely.
    const rec = reconcileVerdicts(expected, out.verdicts);
    expect(rec.missing).toHaveLength(0);
    // Raw responses retained for artifact logging.
    expect(out.rawResponses.map((r) => r.kind)).toEqual(["initial", "id-repair"]);
    expect(out.rawResponses[0].rawText).toBe("raw-initial");
  });

  it("stops after two repair attempts", async () => {
    let followUps = 0;
    const out = await drain(
      runRevalidateIdRepairLoop({
        expected,
        verdicts: [],
        initialRawText: "[]",
        followUp: async () => {
          followUps++;
          return JSON.stringify([
            { findingId: "still_wrong", verdict: "uncertain", reasoning: "x" },
          ]);
        },
        agentLabel: "test",
      }),
    );
    expect(followUps).toBe(2);
    expect(out.repairAttempts).toBe(2);
  });

  it("stops when the repair response is unparseable, keeping prior verdicts", async () => {
    const out = await drain(
      runRevalidateIdRepairLoop({
        expected,
        verdicts: [verdict({ findingId: "finding_aaa" })],
        initialRawText: "[]",
        followUp: async () => "not json at all",
        agentLabel: "test",
      }),
    );
    expect(out.repairAttempts).toBe(1);
    expect(out.verdicts).toHaveLength(1);
    expect(out.rawResponses.at(-1)?.kind).toBe("id-repair");
  });

  it("does nothing without a followUp channel", async () => {
    const out = await drain(
      runRevalidateIdRepairLoop({
        expected,
        verdicts: [],
        initialRawText: "[]",
        followUp: undefined,
        agentLabel: "test",
      }),
    );
    expect(out.repairAttempts).toBe(0);
  });
});

describe("short aliases", () => {
  const aliased = [
    { ...exp("finding_aaa", "src/a.ts", "one"), alias: "F1" },
    { ...exp("finding_bbb", "src/a.ts", "two"), alias: "F2" },
    { ...exp("finding_ccc", "src/b.ts", "three"), alias: "F3" },
  ];

  it("normalizeAliasRef accepts F3 / f3 / #3 / bare 3 and rejects non-aliases", async () => {
    const { normalizeAliasRef } = await import("../reconcile.js");
    expect(normalizeAliasRef("F3")).toBe("3");
    expect(normalizeAliasRef("f3")).toBe("3");
    expect(normalizeAliasRef("#3")).toBe("3");
    expect(normalizeAliasRef(" 3 ")).toBe("3");
    expect(normalizeAliasRef("F03")).toBe("3");
    expect(normalizeAliasRef("finding_abc123")).toBeUndefined();
    expect(normalizeAliasRef("Fix the thing")).toBeUndefined();
    expect(normalizeAliasRef("")).toBeUndefined();
  });

  it("expectedFindingsForBatch assigns F1..Fn in prompt order", async () => {
    const { expectedFindingsForBatch } = await import("../reconcile.js");
    const mkFile = (filePath: string, titles: string[]) =>
      ({
        filePath,
        projectId: "p",
        candidates: [],
        lastScannedAt: "",
        lastScannedRunId: "",
        fileHash: "",
        findings: titles.map((title) => ({
          severity: "HIGH",
          vulnSlug: "s",
          title,
          description: "d",
          lineNumbers: [1],
          recommendation: "r",
          confidence: "high",
        })),
        analysisHistory: [],
        status: "analyzed",
      }) as FileRecord;
    const out = expectedFindingsForBatch([mkFile("a.ts", ["x", "y"]), mkFile("b.ts", ["z"])]);
    expect(out.map((e) => e.alias)).toEqual(["F1", "F2", "F3"]);
  });

  it("reconciles verdicts that echo the alias in any accepted form", () => {
    const res = reconcileVerdicts(aliased, [
      verdict({ findingId: "F1" }),
      verdict({ findingId: "#2" }),
      verdict({ findingId: "f3" }),
    ]);
    expect(res.matches.map((m) => m.expected.findingId).sort()).toEqual([
      "finding_aaa",
      "finding_bbb",
      "finding_ccc",
    ]);
    expect(res.matches.every((m) => m.diagnostic.matchedBy === "finding-id")).toBe(true);
    expect(res.missing).toHaveLength(0);
  });

  it("still accepts the full findingId when the model returns it instead of the alias", () => {
    const res = reconcileVerdicts(aliased, [verdict({ findingId: "finding_bbb" })]);
    expect(res.matches[0].expected.findingId).toBe("finding_bbb");
  });

  it("treats an out-of-range alias as unknown", () => {
    const res = reconcileVerdicts(aliased, [
      verdict({ findingId: "F9" }),
      verdict({ findingId: "F8" }),
    ]);
    expect(res.matches).toHaveLength(0);
    expect(res.unknown).toHaveLength(2);
  });

  it("buildAliasMap + resolveDuplicateRef translate alias references", async () => {
    const { buildAliasMap } = await import("../reconcile.js");
    const file = {
      filePath: "src/a.ts",
      projectId: "p",
      candidates: [],
      lastScannedAt: "",
      lastScannedRunId: "",
      fileHash: "",
      findings: [
        {
          severity: "HIGH",
          vulnSlug: "s",
          title: "one",
          description: "d",
          lineNumbers: [1],
          recommendation: "r",
          confidence: "high",
          findingId: "finding_aaa",
        },
      ],
      analysisHistory: [],
      status: "analyzed",
    } as FileRecord;
    const aliasMap = buildAliasMap(aliased);
    expect(resolveDuplicateRef({ ref: "F1", file, aliasMap })?.finding.findingId).toBe(
      "finding_aaa",
    );
    expect(resolveDuplicateRef({ ref: "F1", file })).toBeUndefined(); // no map, no guess
  });
});

describe("buildRevalidatePrompt alias rendering", () => {
  it("shows short aliases as the Finding ID and lists them in the checklist", async () => {
    const { buildRevalidatePrompt } = await import("../agents/shared.js");
    const file = {
      filePath: "src/a.ts",
      projectId: "p",
      candidates: [],
      lastScannedAt: "",
      lastScannedRunId: "",
      fileHash: "",
      findings: ["alpha issue", "beta issue"].map((title) => ({
        severity: "HIGH" as const,
        vulnSlug: "s",
        title,
        description: "d",
        lineNumbers: [1],
        recommendation: "r",
        confidence: "high" as const,
      })),
      analysisHistory: [],
      status: "analyzed" as const,
    } as FileRecord;

    const { prompt, expected } = buildRevalidatePrompt({
      batch: [file],
      projectRoot: process.cwd(),
      projectInfo: "",
      force: false,
    });

    expect(expected.map((e) => e.alias)).toEqual(["F1", "F2"]);
    expect(prompt).toContain("- **Finding ID:** F1");
    expect(prompt).toContain("- **Finding ID:** F2");
    expect(prompt).toContain('- F1 — "alpha issue"');
    expect(prompt).toContain('- F2 — "beta issue"');
    // The long hash never reaches the model — nothing to truncate or mangle.
    expect(prompt).not.toContain("finding_");
  });
});

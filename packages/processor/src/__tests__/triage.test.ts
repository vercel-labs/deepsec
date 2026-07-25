import { describe, expect, it } from "vitest";
import { parseTriageVerdicts } from "../triage.js";

describe("parseTriageVerdicts", () => {
  const valid = {
    title: "SQL injection",
    priority: "P0",
    exploitability: "trivial",
    impact: "critical",
    reasoning: "single crafted request",
  };

  it("parses fenced JSON verdicts", () => {
    const { verdicts, invalid } = parseTriageVerdicts(
      `\`\`\`json\n${JSON.stringify([valid])}\n\`\`\``,
    );
    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].priority).toBe("P0");
    expect(invalid).toEqual([]);
  });

  it("keeps valid verdicts and reports field-invalid ones instead of writing them", () => {
    // A triage verdict with a bad enum used to be copied verbatim into
    // `finding.triage`; the read-side schema then rejected the finding on
    // the next load and it vanished from reports.
    const { verdicts, invalid } = parseTriageVerdicts(
      JSON.stringify([
        valid,
        { ...valid, title: "bad priority", priority: "P3" },
        { ...valid, title: "bad impact", impact: "CRITICAL" },
      ]),
    );
    expect(verdicts.map((v) => v.title)).toEqual(["SQL injection"]);
    expect(invalid).toHaveLength(2);
    expect(invalid[0].issues).toContain("priority");
    expect(invalid[1].issues).toContain("impact");
  });

  it("returns empty on non-JSON or non-array output", () => {
    expect(parseTriageVerdicts("no json here").verdicts).toEqual([]);
    expect(parseTriageVerdicts('{"not":"an array"}').verdicts).toEqual([]);
  });
});

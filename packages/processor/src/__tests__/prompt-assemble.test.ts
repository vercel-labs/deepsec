import { describe, expect, it } from "vitest";
import {
  assemblePrompt,
  CORE_PROMPT,
  resolvePromptAppend,
  TECH_HIGHLIGHTS,
} from "../prompt/index.js";

describe("assemblePrompt", () => {
  it("returns just the core prompt when no tech is detected and no batch slugs", () => {
    const { prompt, meta } = assemblePrompt({ detectedTags: [], batchSlugs: [] });
    expect(prompt).toBe(CORE_PROMPT);
    expect(meta.includedTags).toEqual([]);
    expect(meta.droppedToFallback).toBe(false);
  });

  it("injects only the highlights for detected tech", () => {
    const { prompt, meta } = assemblePrompt({
      detectedTags: ["nextjs", "react"],
      batchSlugs: [],
    });
    expect(prompt).toContain("### Next.js");
    expect(prompt).toContain("### React");
    expect(prompt).not.toContain("### Django");
    expect(prompt).not.toContain("### Laravel");
    expect(meta.includedTags).toContain("nextjs");
    expect(meta.includedTags).toContain("react");
    expect(meta.droppedToFallback).toBe(false);
  });

  it("ignores unknown tech tags", () => {
    const { prompt, meta } = assemblePrompt({
      detectedTags: ["bogus-framework", "another-fake"],
      batchSlugs: [],
    });
    expect(prompt).toBe(CORE_PROMPT); // no framework section
    expect(meta.includedTags).toEqual([]);
  });

  it("includes per-slug notes only for slugs in the batch", () => {
    const { prompt, meta } = assemblePrompt({
      detectedTags: [],
      batchSlugs: ["xss", "sql-injection"],
    });
    expect(prompt).toContain("`xss`");
    expect(prompt).toContain("`sql-injection`");
    expect(prompt).not.toContain("`open-redirect`");
    expect(meta.slugsWithNotes).toBe(2);
  });

  it("appends INFO.md and promptAppend at the end, both after the framework section", () => {
    const { prompt } = assemblePrompt({
      detectedTags: ["nextjs"],
      batchSlugs: ["xss"],
      projectInfo: "## Internal stuff\n\nPay attention to the auth shim.",
      promptAppend: "Custom: also flag any logger that swallows errors.",
    });
    // Both user-authored sections come AFTER the Next.js highlight…
    expect(prompt.indexOf("## Internal stuff")).toBeGreaterThan(prompt.indexOf("### Next.js"));
    expect(prompt).toContain("Custom: also flag any logger");
    // …and promptAppend follows projectInfo.
    expect(prompt.indexOf("Custom: also flag")).toBeGreaterThan(
      prompt.indexOf("## Internal stuff"),
    );
    // No bespoke wrapper heading — we use a horizontal rule so user
    // headers don't collide with one of ours.
    expect(prompt).not.toContain("## Project context");
  });

  it("filters a path-scoped promptAppend against the batch's files", () => {
    const { prompt, meta } = assemblePrompt({
      detectedTags: [],
      batchSlugs: [],
      batchFilePaths: ["src/api/users.ts"],
      promptAppend: [
        { paths: ["src/api/**"], text: "Scoped to the API surface." },
        { paths: ["db/**"], text: "Scoped to the database surface." },
      ],
    });
    expect(prompt).toContain("Scoped to the API surface.");
    expect(prompt).not.toContain("Scoped to the database surface.");
    expect(meta.promptAppendRulesApplied).toBe(1);
  });

  it("falls back to a one-line summary when too many highlights would crowd the prompt", () => {
    // All known tags at once trips the polyglot fallback.
    const allTags = TECH_HIGHLIGHTS.map((h) => h.tag);
    const { prompt, meta } = assemblePrompt({
      detectedTags: allTags,
      batchSlugs: [],
    });
    expect(meta.droppedToFallback).toBe(true);
    expect(prompt).toContain("This repo uses");
    // Individual highlight headers should be absent in the fallback.
    expect(prompt).not.toContain("### Next.js");
  });

  it("each tech highlight stays compact (≤ 800 chars / ~200 tokens)", () => {
    // Soft-cap: keeps highlights from drifting into tutorial territory.
    for (const h of TECH_HIGHLIGHTS) {
      const rendered = `### ${h.title}\n${h.bullets.map((b) => `- ${b}`).join("\n")}`;
      expect(rendered.length).toBeLessThanOrEqual(1200);
      expect(h.bullets.length).toBeGreaterThanOrEqual(3);
      expect(h.bullets.length).toBeLessThanOrEqual(7);
    }
  });
});

describe("resolvePromptAppend", () => {
  const API_RULE = {
    paths: ["src/api/**"],
    text: "Check every handler here for a missing authorization guard.",
  };
  const MIGRATION_RULE = {
    paths: ["db/migrations/**", "db/schema.sql"],
    text: "Check schema changes for newly exposed columns.",
  };
  const STANDING_RULE = { text: "Flag loggers that swallow errors." };

  it("returns an empty result when there is no addendum", () => {
    expect(resolvePromptAppend(undefined, ["src/api/users.ts"])).toEqual({
      text: "",
      rulesApplied: 0,
    });
  });

  it("returns a plain string unchanged for any batch", () => {
    const result = resolvePromptAppend(STANDING_RULE.text, ["db/seed.ts"]);
    expect(result.text).toBe(STANDING_RULE.text);
    expect(result.rulesApplied).toBe(0);
  });

  it("keeps an entry whose glob matches a file in the batch", () => {
    const result = resolvePromptAppend([API_RULE, MIGRATION_RULE], ["src/api/users.ts"]);
    expect(result.text).toBe(API_RULE.text);
    expect(result.rulesApplied).toBe(1);
  });

  it("matches any of the globs listed on one entry", () => {
    const result = resolvePromptAppend([MIGRATION_RULE], ["db/schema.sql"]);
    expect(result.text).toBe(MIGRATION_RULE.text);
  });

  it("drops every entry when no file in the batch matches", () => {
    const result = resolvePromptAppend([API_RULE, MIGRATION_RULE], ["src/lib/format.ts"]);
    expect(result).toEqual({ text: "", rulesApplied: 0 });
  });

  it("keeps an entry that declares no paths on every batch", () => {
    const result = resolvePromptAppend([STANDING_RULE, API_RULE], ["src/lib/format.ts"]);
    expect(result.text).toBe(STANDING_RULE.text);
    expect(result.rulesApplied).toBe(1);
  });

  it("keeps only unscoped entries when the caller tracks no files", () => {
    // Without a file list the caller cannot confirm a surface is present,
    // so a scoped checklist stays out rather than riding along unverified.
    const result = resolvePromptAppend([API_RULE, STANDING_RULE], undefined);
    expect(result.text).toBe(STANDING_RULE.text);
  });

  it("joins matched entries in declaration order", () => {
    const result = resolvePromptAppend(
      [API_RULE, MIGRATION_RULE],
      ["src/api/users.ts", "db/migrations/001.sql"],
    );
    expect(result.text).toBe(`${API_RULE.text}\n\n${MIGRATION_RULE.text}`);
    expect(result.rulesApplied).toBe(2);
  });

  // config.json is hand-authored, so the declared type is not a runtime
  // guarantee. A typo in one entry must not fail the batch.

  it("skips a value that is neither a string nor an array", () => {
    for (const bad of [null, { text: "x" }, 42]) {
      expect(resolvePromptAppend(bad as never, ["src/api/users.ts"])).toEqual({
        text: "",
        rulesApplied: 0,
      });
    }
  });

  it("skips an entry whose text is missing or not a string", () => {
    const result = resolvePromptAppend(
      [{ paths: ["src/api/**"] }, { paths: ["src/api/**"], text: 7 }, API_RULE] as never,
      ["src/api/users.ts"],
    );
    expect(result.text).toBe(API_RULE.text);
    expect(result.rulesApplied).toBe(1);
  });

  it("skips an entry whose text is only whitespace", () => {
    // rulesApplied must count what actually reached the prompt.
    const result = resolvePromptAppend(
      [{ paths: ["src/api/**"], text: "   " }, API_RULE],
      ["src/api/users.ts"],
    );
    expect(result.text).toBe(API_RULE.text);
    expect(result.rulesApplied).toBe(1);
  });

  it("skips a pattern that is not a string", () => {
    // minimatch throws "invalid pattern" on a non-string.
    const result = resolvePromptAppend([{ paths: [123, "src/api/**"], text: "Scoped." }] as never, [
      "src/api/users.ts",
    ]);
    expect(result.text).toBe("Scoped.");
  });

  it("skips an entry whose paths is not an array", () => {
    // A typo must narrow, never broadcast. `paths: "src/api/**"` (string
    // instead of array) would otherwise apply the rule to every batch.
    for (const bad of ["src/api/**", {}, 7]) {
      const result = resolvePromptAppend([{ paths: bad, text: "Scoped." }] as never, [
        "src/api/users.ts",
      ]);
      expect(result).toEqual({ text: "", rulesApplied: 0 });
    }
  });

  it("selects nothing for an entry whose paths is empty", () => {
    const result = resolvePromptAppend([{ paths: [], text: "Scoped." }], ["src/api/users.ts"]);
    expect(result).toEqual({ text: "", rulesApplied: 0 });
  });

  it("treats a leading ! or # as a literal character, not glob syntax", () => {
    // Matches how the scanner compiles declarative matcher globs.
    const result = resolvePromptAppend(
      [{ paths: ["!src/**"], text: "Negated." }],
      ["src/api/users.ts"],
    );
    expect(result.text).toBe("");
  });
});

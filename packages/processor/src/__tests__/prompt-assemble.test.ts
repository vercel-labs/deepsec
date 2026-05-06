import { describe, expect, it } from "vitest";
import { assemblePrompt, CORE_PROMPT, TECH_HIGHLIGHTS } from "../prompt/index.js";

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

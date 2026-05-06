import { CORE_PROMPT } from "./core.js";
import { highlightForTag, type TechHighlight } from "./highlights.js";
import { noteForSlug } from "./slug-notes.js";

/**
 * Hard cap on the framework-specific section. Polyglot repos (Turborepo
 * with Next.js + Python services + Rails admin) can trip the cap; when
 * exceeded, we drop full highlights and emit a one-line "this repo uses
 * N frameworks: …" fallback instead of crowding the prompt.
 *
 * The cap is approximate (4 chars ≈ 1 token); precise tokenization isn't
 * worth the dependency.
 */
const FRAMEWORK_SECTION_CHAR_BUDGET = 6000;

function approxTokens(s: string): number {
  return Math.ceil(s.length / 4);
}

export interface AssembleParams {
  /**
   * Tech tags detected in the project (from `detectTech()`). When empty,
   * the assembler falls back to the bare core prompt — no framework
   * highlights and no polyglot fallback line.
   */
  detectedTags: string[];
  /**
   * Vulnerability slugs flagged in the current batch. Per-slug notes are
   * only included when their slug appears here, so the prompt scales
   * with what the scanner actually saw — not the entire registry.
   */
  batchSlugs: string[];
  /**
   * Languages of the files in the current batch (canonical names from
   * `LANGUAGE_EXTENSIONS` in @deepsec/scanner: "typescript", "python",
   * "go", etc.). Used to scope highlights to the files that are actually
   * in this batch — a batch of pure Python files in a polyglot Next.js +
   * Django repo doesn't carry the Next.js highlights, even though the
   * project as a whole has the `nextjs` tag.
   *
   * When omitted (or an empty array), no language filtering is applied —
   * every detected tag's highlight is eligible. Pass `[]` only when you
   * truly want all highlights (e.g. tooling that doesn't track files).
   */
  batchLanguages?: string[];
  /**
   * Optional project-specific INFO.md content (already loaded by caller).
   * Appended verbatim if present.
   */
  projectInfo?: string;
  /**
   * Optional `config.json:promptAppend` content from the project. Appended
   * verbatim if present.
   */
  promptAppend?: string;
}

/** Render a highlight as the section it occupies in the final prompt. */
function renderHighlight(h: TechHighlight): string {
  return `### ${h.title}\n${h.bullets.map((b) => `- ${b}`).join("\n")}`;
}

/**
 * Build the framework-specific section. Returns the rendered text and the
 * list of tags whose highlights were actually included (caller logs this
 * for debugging when a cap or skip kicks in).
 *
 * `batchLanguages` (when provided and non-empty) filters the set of
 * eligible highlights to those whose declared `languages` intersect the
 * batch — so a batch of Python files gets Django highlights but not
 * Next.js highlights, even on a polyglot repo where both were detected.
 */
function renderFrameworkSection(
  detectedTags: string[],
  batchLanguages: string[] | undefined,
): {
  text: string;
  includedTags: string[];
  droppedToFallback: boolean;
} {
  const langSet = batchLanguages && batchLanguages.length > 0 ? new Set(batchLanguages) : null;

  const knownHighlights = detectedTags
    .map((t) => highlightForTag(t))
    .filter((h): h is TechHighlight => h !== undefined)
    .filter((h) => {
      if (!langSet) return true; // no filter → keep all
      return h.languages.some((l) => langSet.has(l));
    });

  if (knownHighlights.length === 0) {
    return { text: "", includedTags: [], droppedToFallback: false };
  }

  // Try the full version. If it's under the cap, ship it.
  const fullBody = knownHighlights.map(renderHighlight).join("\n\n");
  const fullSection = `## Threat highlights for this repo's tech stack\n\n${fullBody}`;

  if (fullSection.length <= FRAMEWORK_SECTION_CHAR_BUDGET) {
    return {
      text: fullSection,
      includedTags: knownHighlights.map((h) => h.tag),
      droppedToFallback: false,
    };
  }

  // Polyglot fallback: too many tech packs to ship them all, so drop to a
  // one-line summary. Better to say less than to crowd the prompt and
  // have the model lose focus.
  const titles = knownHighlights.map((h) => h.title).join(", ");
  const fallback =
    `## Tech in this repo\n\nThis repo uses ${knownHighlights.length} known frameworks: ${titles}. ` +
    `Apply standard auth, input validation, and authorization thinking for each — pay particular ` +
    `attention to cross-framework trust boundaries (one framework's "internal" call is another's public endpoint).`;
  return {
    text: fallback,
    includedTags: knownHighlights.map((h) => h.tag),
    droppedToFallback: true,
  };
}

function renderSlugSection(batchSlugs: string[]): string {
  const unique = Array.from(new Set(batchSlugs));
  const lines = unique
    .map((s) => {
      const note = noteForSlug(s);
      return note ? `- \`${s}\`: ${note}` : null;
    })
    .filter((x): x is string => x !== null);

  if (lines.length === 0) return "";
  return `## Slug-specific reviewer notes\n\n${lines.join("\n")}`;
}

export interface AssembleResult {
  /** The fully-assembled prompt, ready to feed to the agent. */
  prompt: string;
  /** Diagnostics — useful for logging/snapshot tests. */
  meta: {
    coreTokens: number;
    frameworkTokens: number;
    slugNoteTokens: number;
    totalTokens: number;
    includedTags: string[];
    droppedToFallback: boolean;
    slugsWithNotes: number;
  };
}

/**
 * Assemble the full investigation prompt. Composition:
 *
 *   [generic core]
 *   ## Threat highlights for this repo's tech stack
 *     ### <tech>
 *       - bullet
 *       - bullet
 *   ## Slug-specific reviewer notes
 *     - `slug`: one sentence
 *   [project INFO.md, verbatim]
 *   [config.json:promptAppend, verbatim]
 *
 * Highlights are scoped to the techs that apply (from detectedTags); slug
 * notes are scoped to slugs that appear in the current batch. Both
 * sections are dropped (or shrunk to a fallback line) when their content
 * is empty or exceeds the size budget.
 */
export function assemblePrompt(params: AssembleParams): AssembleResult {
  const { detectedTags, batchSlugs, batchLanguages, projectInfo, promptAppend } = params;

  const sections: string[] = [CORE_PROMPT];

  const framework = renderFrameworkSection(detectedTags, batchLanguages);
  if (framework.text) sections.push(framework.text);

  const slugSection = renderSlugSection(batchSlugs);
  if (slugSection) sections.push(slugSection);

  // INFO.md and promptAppend are user-authored — they often start with
  // their own H1/H2. Separate with horizontal rules instead of wrapping
  // them in our own header so we never produce two consecutive H2s with
  // nothing between them.
  if (projectInfo && projectInfo.trim().length > 0) {
    sections.push(`---\n\n${projectInfo.trim()}`);
  }
  if (promptAppend && promptAppend.trim().length > 0) {
    sections.push(`---\n\n${promptAppend.trim()}`);
  }

  const prompt = sections.join("\n\n");

  return {
    prompt,
    meta: {
      coreTokens: approxTokens(CORE_PROMPT),
      frameworkTokens: approxTokens(framework.text),
      slugNoteTokens: approxTokens(slugSection),
      totalTokens: approxTokens(prompt),
      includedTags: framework.includedTags,
      droppedToFallback: framework.droppedToFallback,
      slugsWithNotes: slugSection
        ? slugSection.split("\n").filter((l) => l.startsWith("- ")).length
        : 0,
    },
  };
}

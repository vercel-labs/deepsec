import path from "node:path";

/**
 * Map a file extension to a canonical language name. Mirrors
 * `LANGUAGE_EXTENSIONS` in @deepsec/scanner, kept as a small local copy
 * so the processor doesn't have to import it just to classify a path.
 *
 * Returning `null` for unknown extensions is intentional — the assembler
 * treats "no language information" as "include all eligible highlights",
 * which is the right behavior for files we can't classify (Dockerfile,
 * config, etc.).
 */
const EXT_TO_LANGUAGE: Record<string, string> = {
  ".ts": "typescript",
  ".tsx": "typescript",
  ".cts": "typescript",
  ".mts": "typescript",
  ".js": "javascript",
  ".jsx": "javascript",
  ".cjs": "javascript",
  ".mjs": "javascript",
  ".py": "python",
  ".rb": "ruby",
  ".php": "php",
  ".go": "go",
  ".rs": "rust",
  ".java": "java",
  ".kt": "kotlin",
  ".kts": "kotlin",
  ".cs": "csharp",
  ".lua": "lua",
  ".tf": "terraform",
};

function languageForFile(filePath: string): string | null {
  const ext = path.extname(filePath).toLowerCase();
  return EXT_TO_LANGUAGE[ext] ?? null;
}

/**
 * Compute the set of languages present in a batch of files. Returns a
 * sorted, deduped array suitable for passing to `assemblePrompt` as
 * `batchLanguages`.
 */
export function languagesForBatch(filePaths: string[]): string[] {
  const langs = new Set<string>();
  for (const p of filePaths) {
    const l = languageForFile(p);
    if (l) langs.add(l);
  }
  return Array.from(langs).sort();
}

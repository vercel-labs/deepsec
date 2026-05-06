import type { CandidateMatch, MatcherPlugin } from "@deepsec/core";

/**
 * Filesystem-write sites that operate on a non-literal path. Without an
 * explicit canonical-path / realpath / startsWith(rootDir) guard, attackers
 * can place a symlink at any path component to escape the intended root
 * (CWE-22 + CWE-59). The agent's job is to confirm whether the call site
 * has a proper boundary check.
 */
const PATTERNS: { regex: RegExp; label: string }[] = [
  {
    regex:
      /\bfs\.(?:mkdir|writeFile|createWriteStream|copyFile|symlink|link|rename|appendFile|chmod|chown|truncate)(?:Sync)?\s*\(\s*`[^`]*\$\{/,
    label: "fs write to template-literal path",
  },
  {
    regex:
      /\bfsp?\.(?:mkdir|writeFile|copyFile|symlink|link|rename|appendFile|chmod|chown|truncate)\s*\(\s*`[^`]*\$\{/,
    label: "fsp/fs.promises write to template-literal path",
  },
  {
    regex:
      /\bfs\.(?:mkdir|writeFile|createWriteStream|copyFile|symlink|link|rename|appendFile)(?:Sync)?\s*\(\s*[A-Za-z_$][\w$]*\s*\+\s*/,
    label: "fs write to concatenated path",
  },
  {
    regex:
      /\bfs\.(?:mkdir|writeFile|createWriteStream|copyFile|symlink|link|rename|appendFile)(?:Sync)?\s*\(\s*path\.join\([^)]*req\./,
    label: "fs write to path.join with req.* component",
  },
  {
    regex:
      /\bfs\.(?:mkdir|writeFile|createWriteStream|copyFile|symlink|link|rename|appendFile)(?:Sync)?\s*\(\s*path\.resolve\([^)]*req\./,
    label: "fs write to path.resolve with req.* component",
  },
];

const HAS_BOUNDARY_HINT =
  /\b(?:realpath|fs\.realpath|path\.relative|startsWith\s*\(\s*(?:root|base)|resolveWritablePathWithinRoot|withinRoot|insideRoot)\b/;

export const fsWriteSymlinkBoundaryMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "fs-write-symlink-boundary",
  description:
    "Filesystem write to dynamic path — verify symlink boundary check (realpath/canonical resolve)",
  filePatterns: ["**/*.{ts,tsx,js,jsx,mjs,cjs}"],
  examples: [
    `fs.writeFile(\`/tmp/uploads/\${name}\`, data, () => {});`,
    `fs.mkdirSync(\`/var/data/\${userId}\`);`,
    `fs.createWriteStream(\`/cache/\${id}.bin\`);`,
    `fs.copyFileSync(\`/tmp/\${dest}\`, src);`,
    `fs.symlinkSync(target, \`/links/\${name}\`);
fs.symlinkSync(\`/links/\${name}\`, target);`,
    `fs.appendFileSync(\`/logs/\${name}.log\`, line);`,
    `fsp.writeFile(\`/data/\${id}.json\`, JSON.stringify(payload));`,
    `await fsp.copyFile(\`/tmp/\${dest}\`, src);`,
    `fs.writeFileSync(rootDir + "/" + name, data);`,
    `fs.mkdirSync(baseDir + relative);`,
    `fs.writeFileSync(path.join(uploadDir, req.body.name), buf);`,
    `fs.writeFile(path.resolve(uploadDir, req.params.id), data, () => {});`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)$/.test(filePath)) return [];
    if (/\.d\.ts$/.test(filePath)) return [];

    // Quick global boundary-check heuristic: if the file uses a known guard
    // helper at all, it's much less likely to be vulnerable. Skip unless the
    // dynamic-path call sits clearly outside that guard's scope.
    const hasBoundaryHelper = HAS_BOUNDARY_HINT.test(content);

    const lines = content.split("\n");
    const matches: CandidateMatch[] = [];

    for (const { regex, label } of PATTERNS) {
      const hitLines: number[] = [];
      const snippets: string[] = [];

      for (let i = 0; i < lines.length; i++) {
        if (!regex.test(lines[i])) continue;

        // Suppress when there's a boundary helper invoked within the same
        // ~5-line window — the file uses guards consistently, this site is
        // probably fine. Imperfect, but cuts the obvious noise.
        if (hasBoundaryHelper) {
          const window = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 5)).join("\n");
          if (HAS_BOUNDARY_HINT.test(window)) continue;
        }

        hitLines.push(i + 1);
        const start = Math.max(0, i - 2);
        const end = Math.min(lines.length, i + 3);
        snippets.push(lines.slice(start, end).join("\n"));
      }

      if (hitLines.length > 0) {
        matches.push({
          vulnSlug: "fs-write-symlink-boundary",
          lineNumbers: hitLines,
          snippet: snippets[0],
          matchedPattern: label,
        });
      }
    }

    return matches;
  },
};

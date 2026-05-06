import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * GitHub Actions workflow + composite-action security risks (supply chain).
 *
 * Patterns:
 *   - `pull_request_target` triggers — run on the base branch with secrets
 *     and can checkout attacker code from the PR
 *   - `actions/checkout@<branch>` or unpinned third-party actions — mutable refs
 *   - `${{ github.event.pull_request.* }}` / `github.event.head_commit.message`
 *     interpolated into `run:` blocks → shell injection
 *   - `secrets.*` referenced in steps that run untrusted code (PR checkouts,
 *     external scripts, building untrusted Dockerfiles)
 *   - `permissions: write-all` or absent permissions block (defaults to broad)
 *   - `id-token: write` combined with no audience binding
 */
export const githubWorkflowSecurityMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "github-workflow-security",
  description: "GitHub Actions workflow / composite-action with supply-chain or injection risk",
  filePatterns: [
    ".github/workflows/**/*.yml",
    ".github/workflows/**/*.yaml",
    ".github/actions/**/*.yml",
    ".github/actions/**/*.yaml",
  ],
  requires: { tech: ["github-actions"] },
  examples: [
    `on:\n  pull_request_target:\n    types: [opened]`,
    `on:\n  workflow_run:\n    workflows: [build]`,
    `      - uses: actions/checkout@main`,
    `      - uses: actions/setup-node@v3`,
    `        run: echo "\${{ github.event.pull_request.title }}"`,
    `        run: git log \${{ github.head_ref }}`,
    `          token: \${{ secrets.GITHUB_TOKEN }}`,
    `permissions: write-all`,
    `permissions:\n  id-token: write\n  contents: read`,
    `      - run: |\n          echo \${{ github.event.pull_request.head.ref }}`,
    `      - run: curl -fsSL https://example.com/install.sh | sh`,
  ],
  match(content) {
    const lines = content.split("\n");
    const hitLines: number[] = [];
    const labels = new Set<string>();
    let firstContext: string | undefined;

    const PATTERNS: { regex: RegExp; label: string }[] = [
      {
        regex: /^\s*-\s*pull_request_target\b|^\s*pull_request_target\s*:/,
        label: "pull_request_target trigger",
      },
      { regex: /^\s*-\s*workflow_run\b|^\s*workflow_run\s*:/, label: "workflow_run trigger" },
      {
        regex: /\buses\s*:\s*[\w-]+\/[\w./-]+@(?:main|master|v?\d+|develop)\s*$/m,
        label: "unpinned action ref (branch/major-tag)",
      },
      {
        regex: /\$\{\{\s*github\.event\.(?:pull_request|head_commit|comment|issue|review)\.\w+/,
        label: "github.event interpolation in run:",
      },
      { regex: /\$\{\{\s*github\.head_ref\s*\}\}/, label: "github.head_ref in script" },
      { regex: /\bsecrets\.[A-Z_][A-Z0-9_]+/, label: "secret reference" },
      { regex: /^\s*permissions\s*:\s*write-all\b/, label: "permissions: write-all" },
      { regex: /\bid-token\s*:\s*write\b/, label: "id-token: write (OIDC)" },
      { regex: /\brun\s*:\s*\|.*\$\{\{[^}]*\}\}/s, label: "run block interpolating expression" },
      { regex: /\bcurl\s+[^|]*\|\s*(?:sh|bash)\b/, label: "curl | sh in workflow" },
    ];

    for (let i = 0; i < lines.length; i++) {
      for (const { regex, label } of PATTERNS) {
        if (regex.test(lines[i])) {
          hitLines.push(i + 1);
          labels.add(label);
          if (firstContext === undefined) {
            const s = Math.max(0, i - 2);
            const e = Math.min(lines.length, i + 3);
            firstContext = lines.slice(s, e).join("\n");
          }
          break;
        }
      }
    }

    // Always-flag fallback: any workflow file is part of the supply chain.
    if (hitLines.length === 0) {
      const anchor = lines.findIndex((l) => /^\s*(?:on|jobs|name)\s*:/.test(l));
      if (anchor === -1) return [];
      const s = Math.max(0, anchor);
      const e = Math.min(lines.length, anchor + 5);
      const match: CandidateMatch = {
        vulnSlug: "github-workflow-security",
        lineNumbers: [anchor + 1],
        snippet: lines.slice(s, e).join("\n"),
        matchedPattern: "GitHub workflow file (path-based, no specific risk pattern)",
      };
      return [match];
    }

    const match: CandidateMatch = {
      vulnSlug: "github-workflow-security",
      lineNumbers: hitLines,
      snippet: firstContext ?? "",
      matchedPattern: Array.from(labels).slice(0, 4).join(", "),
    };
    return [match];
  },
};

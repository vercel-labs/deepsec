import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Wide-net matcher: shell scripts that run *inside* sandbox container
 * images at runtime — paths under `containers/sandbox-NAME/scripts/`
 * (and similar bin scripts baked into the image), plus git-credential
 * helpers and other auth shims inside the sandbox.
 *
 * These execute as part of the customer-facing environment and frequently:
 *   - take env-var input that the user controls (e.g. `$TARGET_PORT`,
 *     `$SANDBOX_*`, `$CONTAINER_*`)
 *   - invoke long-running daemons (code-server, ttyd, sync daemons) that
 *     bind to `0.0.0.0` inside the container
 *   - shuffle credentials between `git`, `gh`, and `~/.config/*`
 *
 * Each one is a plausible escape vector if env-var input or filesystem
 * state can be influenced from outside the intended boundary.
 */
export const sandboxRuntimeScriptMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "sandbox-runtime-script",
  description:
    "Shell script that runs inside a sandbox container at runtime (customer-facing surface)",
  filePatterns: [
    "**/containers/**/scripts/**/*.sh",
    "**/containers/**/bin/**/*.sh",
    "**/containers/**/*credential*.sh",
    "**/containers/**/entrypoint*.sh",
    "**/containers/**/start*.sh",
  ],
  examples: [
    `#!/bin/bash\neval "$USER_INPUT"`,
    `#!/bin/bash\nbash -c "echo \${USER_NAME}"`,
    `#!/bin/bash\necho $TARGET_PORT > /tmp/x`,
    `#!/bin/bash\nsudo chmod 755 /tmp/file`,
    `#!/bin/bash\nexec ttyd --port 7681 --interface 0.0.0.0`,
    `#!/bin/bash\ngit config --global credential.helper store`,
    `#!/bin/bash\necho $SANDBOX_ID\necho $CONTAINER_NAME`,
    `#!/bin/bash\ncurl -fsSL https://example.com/install.sh | bash`,
    `#!/bin/bash\nnohup ./daemon &`,
    `#!/bin/bash\necho hello`,
  ],
  match(content, filePath) {
    // Not the build/codegen scripts — those are container-build-time
    if (/scripts\/(?:build|generate-(?:go|ts)|test|publish[-_])/.test(filePath)) return [];

    const lines = content.split("\n");
    const hitLines: number[] = [];
    const labels = new Set<string>();
    let firstContext: string | undefined;

    const PATTERNS: { regex: RegExp; label: string }[] = [
      { regex: /\b(?:eval|exec)\s+["'`]?\$/, label: "eval/exec with env var" },
      { regex: /\bbash\s+-c\s+["'`].*\$\{?[A-Z]/, label: "bash -c with env interpolation" },
      { regex: /\$\{?[A-Z][A-Z0-9_]+\}?[^"'`)]/, label: "unquoted env var expansion" },
      { regex: /\b(?:sudo|su\s|chmod|chown)\s/, label: "privilege/permission op" },
      { regex: /\b0\.0\.0\.0\b/, label: "binds 0.0.0.0" },
      {
        regex: /\bgit\s+(?:config|credential|push|fetch|clone)\b/,
        label: "git credential / network op",
      },
      {
        regex: /\b(?:TARGET|SANDBOX|CONTAINER)_[A-Z0-9_]+\b/,
        label: "TARGET_/SANDBOX_/CONTAINER_ env",
      },
      { regex: /\bcurl\b[^|]*\|[\s]*(?:sh|bash)/, label: "curl | sh pattern" },
      { regex: /\b(?:nohup|&\s*$|disown)\b/, label: "background daemon launch" },
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

    // Always-flag fallback: if the path matched filePatterns and we got here,
    // the script runs inside a sandbox container at runtime. Even simple
    // `exec foo --port 7681` daemons (ttyd, code-server) are entry points
    // worth a human/AI read.
    if (hitLines.length === 0) {
      const firstNonShebang = lines.findIndex(
        (l, idx) => idx > 0 && l.trim() && !l.trim().startsWith("#"),
      );
      const anchor = firstNonShebang === -1 ? 1 : firstNonShebang + 1;
      const s = Math.max(0, anchor - 2);
      const e = Math.min(lines.length, anchor + 5);
      const match: CandidateMatch = {
        vulnSlug: "sandbox-runtime-script",
        lineNumbers: [anchor],
        snippet: lines.slice(s, e).join("\n"),
        matchedPattern: "container-runtime script (path-based)",
      };
      return [match];
    }
    const match: CandidateMatch = {
      vulnSlug: "sandbox-runtime-script",
      lineNumbers: hitLines,
      snippet: firstContext ?? "",
      matchedPattern: Array.from(labels).slice(0, 4).join(", "),
    };
    return [match];
  },
};

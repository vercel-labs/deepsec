import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Final-stage image with no `USER` directive (or `USER root`) after the last
 * `FROM`. The container then runs as UID 0, widening the blast radius of any
 * escape or LPE exploit inside the image.
 *
 * Multi-stage builds are handled by tracking the last FROM stage in the file.
 */
export const dockerfileRunAsRootMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "dockerfile-run-as-root",
  description: "Final Dockerfile stage runs as root (no USER directive, or USER root)",
  filePatterns: ["**/Dockerfile", "**/Dockerfile.*", "**/*.Dockerfile"],
  requires: { tech: ["docker"] },
  examples: [
    `FROM node:20\nWORKDIR /app\nCOPY . .\nCMD ["node", "index.js"]`,
    `FROM ubuntu:22.04\nRUN apt-get update\nUSER root\nCMD ["bash"]`,
    `FROM python:3.11\nUSER 0\nCMD ["python", "app.py"]`,
    `FROM alpine\nFROM debian:bookworm\nCOPY --from=0 /bin/app /bin/app\nCMD ["/bin/app"]`,
  ],
  match(content) {
    const lines = content.split("\n");

    // Find the last `FROM` — that's the final image stage.
    let finalStageStart = -1;
    let finalStageBase = "";
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(/^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)/i);
      if (m) {
        finalStageStart = i;
        finalStageBase = m[1];
      }
    }
    if (finalStageStart === -1) return [];

    // If the final stage is `FROM scratch` with no further directives, it is
    // a binary-only layer and doesn't run shell — skip.
    if (finalStageBase === "scratch") {
      const hasDirectives = lines
        .slice(finalStageStart + 1)
        .some((l) => /^\s*(CMD|ENTRYPOINT|RUN)\b/i.test(l));
      if (!hasDirectives) return [];
    }

    // Walk the final stage, find the last effective USER directive.
    let lastUser: string | null = null;
    for (let i = finalStageStart + 1; i < lines.length; i++) {
      const m = lines[i].match(/^\s*USER\s+(\S+)/i);
      if (m) lastUser = m[1];
    }

    const runsAsRoot = lastUser === null || /^(root|0)(:|\s|$)/.test(lastUser);
    if (!runsAsRoot) return [];

    const snipStart = Math.max(0, finalStageStart);
    const snipEnd = Math.min(lines.length, finalStageStart + 3);
    const match: CandidateMatch = {
      vulnSlug: "dockerfile-run-as-root",
      lineNumbers: [finalStageStart + 1],
      snippet: lines.slice(snipStart, snipEnd).join("\n"),
      matchedPattern:
        lastUser === null
          ? "Final stage has no USER directive"
          : `Final stage ends with USER ${lastUser}`,
    };
    return [match];
  },
};

import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * K8s Deployment/Pod manifests that either:
 *   (a) Run the `secrets-init-container` image (the official decrypt pipeline)
 *   (b) Reference env vars prefixed with `ENCRYPTED_V1_` / `ENCRYPTED_V2_`
 *       (consumers of the init-container pipeline)
 *
 * These pods rely on the init-container writing decrypted values into a
 * shared `decrypted-env` volume. Security of the pod's secret handling
 * depends on:
 *   - The init container image being pinned (version, digest)
 *   - The `decrypted-env` volumeMount being an `emptyDir` with `memory` medium
 *     (never persisted to disk)
 *   - The main container not logging / re-emitting those env vars
 *   - No sidecar container with the same mount that might exfiltrate
 */
export const k8sSecretsInitContainerMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "k8s-secrets-init-container",
  description: "K8s manifest uses the secrets-init-container decryption pipeline",
  filePatterns: ["**/*.yaml", "**/*.yml"],
  examples: [
    `initContainers:\n  - name: init\n    image: ghcr.io/example/secrets-init-container:v1`,
    `env:\n    name: ENCRYPTED_V1_DATABASE_URL\n    value: "..."`,
    `env:\n    name: ENCRYPTED_V2_API_TOKEN\n    value: "..."`,
    `volumeMounts:\n  - name: decrypted\n    mountPath: /usr/share`,
    `volumes:\n  - name: decrypted-env\n    emptyDir:\n      medium: Memory`,
    `secretKeyRef:\n  name: encrypted-v1-database\n  key: payload`,
  ],
  match(content, filePath) {
    if (/(?:^|\/)(?:node_modules|vendor|charts|\.github)\//.test(filePath)) return [];

    const lines = content.split("\n");
    const hitLines: number[] = [];
    const labels = new Set<string>();
    let firstContext: string | undefined;

    const PATTERNS: { regex: RegExp; label: string }[] = [
      { regex: /\bsecrets-init-container\b/, label: "secrets-init-container image reference" },
      {
        regex: /^\s*name\s*:\s*ENCRYPTED_V[12]_[A-Z0-9_]+/,
        label: "ENCRYPTED_V*_ env var (init-container consumer)",
      },
      {
        regex: /^\s*mountPath\s*:\s*["']?\/usr\/share["']?\s*$/,
        label: "/usr/share decrypted-env mount",
      },
      { regex: /\bdecrypted-env\b/, label: "decrypted-env volume reference" },
      { regex: /^\s*name\s*:\s*encrypted-v[12]-\S+/, label: "encrypted-v{1,2}-* secret name" },
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

    if (hitLines.length === 0) return [];
    const match: CandidateMatch = {
      vulnSlug: "k8s-secrets-init-container",
      lineNumbers: hitLines,
      snippet: firstContext ?? "",
      matchedPattern: Array.from(labels).slice(0, 5).join(", "),
    };
    return [match];
  },
};

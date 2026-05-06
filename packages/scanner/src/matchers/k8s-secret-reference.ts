import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Any Kubernetes manifest that references a Secret — either directly via
 * `valueFrom.secretKeyRef`, as a Volume (`secretName:` under `volumes:`), or
 * through ExternalSecret / SealedSecret / vault-injector annotations.
 *
 * Coupled with the AI pass to verify:
 *   - the secret is consumed through the official `secrets-init-container`
 *     pipeline (env vars prefixed `ENCRYPTED_V1_*` / `ENCRYPTED_V2_*`), not
 *     a raw plaintext K8s Secret
 *   - the consuming pod's ServiceAccount is appropriately scoped (no cluster-
 *     wide access to all secrets)
 *   - no `vault.hashicorp.com/agent-inject` or similar that would bypass the
 *     central decryption pipeline
 *   - no `type: Opaque` Secret manifests committed with plaintext `data:` /
 *     `stringData:` values
 */
export const k8sSecretReferenceMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "k8s-secret-reference",
  description: "K8s manifest references a Secret (secretKeyRef, secretName, ExternalSecret, etc.)",
  filePatterns: ["**/*.yaml", "**/*.yml"],
  examples: [
    `env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db\n        key: password`,
    `volumes:\n  - name: certs\n    secret:\n      secretName: tls-certs`,
    `apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\ntype: Opaque`,
    `apiVersion: external-secrets.io/v1beta1\nkind: ExternalSecret\nmetadata:\n  name: db`,
    `metadata:\n  annotations:\n    vault.hashicorp.com/agent-inject: "true"`,
    `spec:\n  containers:\n    - image: ghcr.io/example/secrets-init-container:v1\n      name: init`,
    `apiVersion: v1\nkind: Secret\nstringData:\n  password: hunter2-very-secret`,
    `env:\n  - name: API_TOKEN\n    value: "AKIAIOSFODNN7EXAMPLE_aws_access_key"`,
  ],
  match(content, filePath) {
    // Avoid scanning gitignored / generated yaml (tests, vendored charts)
    if (/(?:^|\/)(?:node_modules|vendor|charts|\.github)\//.test(filePath)) return [];

    const lines = content.split("\n");
    const hitLines: number[] = [];
    const labels = new Set<string>();
    let firstContext: string | undefined;

    const PATTERNS: { regex: RegExp; label: string }[] = [
      { regex: /^\s*-?\s*secretKeyRef\s*:/, label: "env.valueFrom.secretKeyRef" },
      { regex: /^\s*secretName\s*:\s*\S/, label: "volumes.secret.secretName" },
      {
        regex:
          /^\s*kind\s*:\s*(?:Secret|ExternalSecret|SealedSecret|ClusterSecretStore|SecretStore)\b/,
        label: "Secret kind manifest",
      },
      { regex: /\bexternal-secrets\.io\//, label: "external-secrets.io CRD" },
      { regex: /\bvault\.hashicorp\.com\/agent-inject\b/, label: "vault-injector annotation" },
      { regex: /\bsecrets-init-container\b/, label: "secrets-init-container reference" },
      { regex: /^\s*stringData\s*:/, label: "Secret stringData (plaintext in manifest!)" },
      // Commonly leaked: env var values that are literal secrets
      {
        regex: /^\s*value\s*:\s*(?:['"]?[A-Za-z0-9+/=_-]{24,})/,
        label: "env.value literal (possibly a secret)",
      },
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
      vulnSlug: "k8s-secret-reference",
      lineNumbers: hitLines,
      snippet: firstContext ?? "",
      matchedPattern: Array.from(labels).slice(0, 5).join(", "),
    };
    return [match];
  },
};

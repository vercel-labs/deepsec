import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Terraform IAM policy / KMS / S3 / SNS / SQS resource policies that grant
 * over-broad access:
 *   - `actions = ["*"]`
 *   - `resources = ["*"]`
 *   - `principals { type = "AWS"; identifiers = ["*"] }`
 *   - `Principal = "*"` in inline JSON policies
 *   - `effect = "Allow"` paired with any wildcard above
 *
 * Targets `data "aws_iam_policy_document" "..." {}` blocks, inline
 * `policy = jsonencode({...})`, KMS key policy attribute, S3 bucket policy.
 */
export const tfIamWildcardMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "tf-iam-wildcard",
  description: "Terraform IAM/KMS/S3/SNS policy with wildcard Action/Resource/Principal",
  filePatterns: ["**/*.tf", "**/*.tf.json", "**/*.hcl"],
  requires: { tech: ["terraform"] },
  examples: [
    `    actions = ["*"]`,
    `"Action": "*",`,
    `    resources = ["*"]`,
    `"Resource": "*",`,
    `"Principal": "*",`,
    `"AWS": "*"`,
    `    identifiers = ["*"]`,
  ],
  match(content) {
    const lines = content.split("\n");
    const hitLines: number[] = [];
    const labels = new Set<string>();
    let firstContext: string | undefined;

    const PATTERNS: { regex: RegExp; label: string }[] = [
      // actions = ["*"]   or  Action = "*"
      { regex: /^\s*actions\s*=\s*\[\s*['"]\*['"]\s*\]/i, label: 'actions = ["*"]' },
      { regex: /['"]Action['"]\s*:\s*['"]\*['"]/i, label: 'Action = "*" (JSON)' },
      // resources = ["*"]
      { regex: /^\s*resources\s*=\s*\[\s*['"]\*['"]\s*\]/i, label: 'resources = ["*"]' },
      { regex: /['"]Resource['"]\s*:\s*['"]\*['"]/i, label: 'Resource = "*" (JSON)' },
      // principal "*"
      { regex: /['"]Principal['"]\s*:\s*['"]\*['"]/i, label: 'Principal = "*" (JSON)' },
      { regex: /['"]AWS['"]\s*:\s*['"]\*['"]/i, label: '"AWS": "*" trust' },
      // principals block { type = "AWS"; identifiers = ["*"] }
      { regex: /\bidentifiers\s*=\s*\[\s*['"]\*['"]\s*\]/i, label: 'identifiers = ["*"]' },
      // assume_role_policy with star
      {
        regex: /\bassume_role_policy\s*=\s*[^"]*\bAWS['"]\s*:\s*['"]\*['"]/i,
        label: "assume_role with AWS:*",
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
      vulnSlug: "tf-iam-wildcard",
      lineNumbers: hitLines,
      snippet: firstContext ?? "",
      matchedPattern: Array.from(labels).slice(0, 4).join(", "),
    };
    return [match];
  },
};

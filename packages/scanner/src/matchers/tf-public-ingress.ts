import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Terraform `aws_security_group_rule` / inline `ingress {}` blocks /
 * `aws_network_acl_rule` with `cidr_blocks = ["0.0.0.0/0"]` (or `::/0`)
 * and a port other than 443 (HTTPS) or 80 (HTTP redirect).
 *
 * Also catches `aws_eks_cluster.vpc_config.endpoint_public_access = true`
 * blocks that don't pair with `endpoint_public_access_cidrs`.
 */
export const tfPublicIngressMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "tf-public-ingress",
  description:
    "Terraform security-group / NACL / EKS ingress allowing 0.0.0.0/0 on non-HTTPS ports",
  filePatterns: ["**/*.tf", "**/*.tf.json", "**/*.hcl"],
  requires: { tech: ["terraform"] },
  examples: [
    `ingress {\n  from_port = 22\n  to_port = 22\n  protocol = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}`,
    `ingress {\n  from_port = 3306\n  to_port = 3306\n  protocol = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}`,
    `resource "aws_security_group_rule" "open" {\n  type = "ingress"\n  from_port = 5432\n  to_port = 5432\n  cidr_blocks = ["0.0.0.0/0"]\n}`,
    `vpc_config {\n  endpoint_public_access = true\n  subnet_ids = var.subnets\n}`,
  ],
  match(content) {
    const lines = content.split("\n");
    const hitLines: number[] = [];
    const labels = new Set<string>();
    let firstContext: string | undefined;

    // Accumulate ingress/sg-rule blocks (multi-line) — we look for cidr=0.0.0.0/0
    // along with a port that isn't 443/80.
    const SENSITIVE_PORTS =
      /\b(?:from_port|to_port|port)\s*=\s*(?:22|3389|5432|3306|6379|27017|9200|9300|11211|5601|8086|9092|2049|445|1433|5984|9300|9000|8080|3000|5000|8000|9090|9443|6443|10250|2375|2376|2377|7000|7001|9999|11210|13316)\b/;

    const blocks: { start: number; text: string }[] = [];
    let i = 0;
    while (i < lines.length) {
      const line = lines[i];
      // ingress { … }, egress { … }, resource "aws_security_group_rule" { … }, resource "aws_network_acl_rule" { … }
      const isStart =
        /^\s*(?:ingress|egress)\s*\{|resource\s+"aws_(?:security_group_rule|network_acl_rule)"/.test(
          line,
        );
      if (!isStart) {
        i++;
        continue;
      }
      const start = i;
      let depth = 0;
      let started = false;
      let text = "";
      outer: for (let j = i; j < lines.length && j < i + 40; j++) {
        text += (started ? "\n" : "") + lines[j];
        for (const ch of lines[j]) {
          if (ch === "{") {
            depth++;
            started = true;
          } else if (ch === "}") {
            depth--;
            if (started && depth === 0) {
              i = j;
              break outer;
            }
          }
        }
      }
      blocks.push({ start, text });
      i++;
    }

    for (const b of blocks) {
      const hasOpenCidr =
        /\b(?:cidr_blocks|cidr_block)\s*=\s*\[?\s*['"]0\.0\.0\.0\/0['"]|::\/0/.test(b.text);
      if (!hasOpenCidr) continue;
      const hasSensitivePort = SENSITIVE_PORTS.test(b.text);
      // 80/443 only (web-facing) is allowed
      const hasOnlyWebPort =
        /\bfrom_port\s*=\s*(?:80|443)\b/.test(b.text) &&
        /\bto_port\s*=\s*(?:80|443)\b/.test(b.text) &&
        !hasSensitivePort;
      if (hasOnlyWebPort) continue;
      hitLines.push(b.start + 1);
      labels.add("0.0.0.0/0 ingress on non-web port");
      if (firstContext === undefined) {
        const s = Math.max(0, b.start - 1);
        const e = Math.min(lines.length, b.start + b.text.split("\n").length + 1);
        firstContext = lines.slice(s, e).join("\n");
      }
    }

    // EKS public endpoint
    for (let j = 0; j < lines.length; j++) {
      if (/\bendpoint_public_access\s*=\s*true/.test(lines[j])) {
        // Look at +/- 8 lines for endpoint_public_access_cidrs
        const span = lines.slice(Math.max(0, j - 8), Math.min(lines.length, j + 9)).join("\n");
        if (!/\bendpoint_public_access_cidrs\b/.test(span)) {
          hitLines.push(j + 1);
          labels.add("EKS public endpoint without CIDR allow-list");
          if (firstContext === undefined) {
            const s = Math.max(0, j - 2);
            const e = Math.min(lines.length, j + 4);
            firstContext = lines.slice(s, e).join("\n");
          }
        }
      }
    }

    if (hitLines.length === 0) return [];
    const match: CandidateMatch = {
      vulnSlug: "tf-public-ingress",
      lineNumbers: hitLines,
      snippet: firstContext ?? "",
      matchedPattern: Array.from(labels).slice(0, 3).join(", "),
    };
    return [match];
  },
};

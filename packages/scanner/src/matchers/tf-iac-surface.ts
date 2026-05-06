import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Wide-net entry-point matcher for any Terraform / Sentinel / Packer / HCL
 * source that defines security-critical infrastructure: IAM, KMS, EKS,
 * RBAC, security groups, VPC peering, S3 bucket policies, kubernetes
 * resources, secret-encryption modules, OIDC providers, Route53.
 *
 * Pure-data files (variable defaults, output names) without those resource
 * types aren't flagged.
 */
export const tfIacSurfaceMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "tf-iac-surface",
  description: "Terraform/HCL/Sentinel file declaring security-critical infrastructure resources",
  filePatterns: ["**/*.tf", "**/*.tf.json", "**/*.hcl", "**/*.sentinel"],
  requires: { tech: ["terraform"] },
  examples: [
    `resource "aws_iam_role" "service" {`,
    `resource "aws_iam_policy_attachment" "admin" {`,
    `resource "aws_kms_key" "main" {`,
    `resource "aws_eks_cluster" "main" {`,
    `resource "aws_security_group" "web" {`,
    `resource "aws_network_acl" "main" {`,
    `resource "aws_vpc_endpoint" "s3" {`,
    `resource "aws_s3_bucket_policy" "logs" {`,
    `resource "aws_route53_record" "www" {`,
    `resource "aws_secretsmanager_secret" "db" {`,
    `resource "aws_lb_listener" "https" {`,
    `resource "kubernetes_cluster_role" "admin" {`,
    `resource "helm_release" "prom" {`,
    `data "aws_iam_policy_document" "doc" {`,
    `import "tfplan"`,
  ],
  match(content, filePath) {
    if (/\.terraform\//.test(filePath)) return [];

    const PATTERNS: { regex: RegExp; label: string }[] = [
      {
        regex:
          /^\s*resource\s+"aws_iam_(?:role|policy|user|group|policy_attachment|access_key|service_linked_role|openid_connect_provider|saml_provider|role_policy|role_policy_attachment|user_policy|group_policy)"\s+/m,
        label: "aws_iam_*",
      },
      { regex: /^\s*resource\s+"aws_kms_(?:key|alias|grant|key_policy)"\s+/m, label: "aws_kms_*" },
      {
        regex:
          /^\s*resource\s+"aws_eks_(?:cluster|node_group|fargate_profile|access_entry|access_policy_association|identity_provider_config|addon|pod_identity_association)"\s+/m,
        label: "aws_eks_*",
      },
      { regex: /^\s*resource\s+"aws_security_group(?:_rule)?"\s+/m, label: "aws_security_group" },
      {
        regex: /^\s*resource\s+"aws_network_acl(?:_rule|_association)?"\s+/m,
        label: "aws_network_acl_*",
      },
      {
        regex: /^\s*resource\s+"aws_vpc(?:_peering_connection|_endpoint|_endpoint_policy)?"\s+/m,
        label: "aws_vpc_*",
      },
      {
        regex:
          /^\s*resource\s+"aws_s3_bucket(?:_policy|_public_access_block|_versioning|_server_side_encryption_configuration|_acl|_lifecycle_configuration|_logging|_object_lock_configuration|_replication_configuration)?"\s+/m,
        label: "aws_s3_bucket_*",
      },
      {
        regex:
          /^\s*resource\s+"aws_route53_(?:record|zone|zone_association|delegation_set|health_check)"\s+/m,
        label: "aws_route53_*",
      },
      {
        regex:
          /^\s*resource\s+"aws_secretsmanager_(?:secret|secret_version|secret_policy|secret_rotation)"\s+/m,
        label: "aws_secretsmanager_*",
      },
      {
        regex: /^\s*resource\s+"aws_lb_listener(?:_rule|_certificate)?"\s+/m,
        label: "aws_lb_listener_*",
      },
      {
        regex:
          /^\s*resource\s+"kubernetes_(?:secret|cluster_role|cluster_role_binding|role|role_binding|service_account|network_policy|pod_security_policy|namespace|config_map)(?:_v1)?"\s+/m,
        label: "kubernetes_*",
      },
      { regex: /^\s*resource\s+"helm_release"\s+/m, label: "helm_release" },
      { regex: /^\s*data\s+"aws_iam_policy_document"\s+/m, label: "aws_iam_policy_document data" },
      // Sentinel policies
      { regex: /^\s*(?:rule|policy|main)\s*=\s*function\s*\(/m, label: "Sentinel rule/policy" },
      { regex: /^\s*import\s+"tfplan(?:-functions)?"/m, label: "Sentinel tfplan import" },
    ];

    const lines = content.split("\n");
    const hitLines: number[] = [];
    const labels = new Set<string>();
    let firstContext: string | undefined;

    for (let i = 0; i < lines.length; i++) {
      for (const { regex, label } of PATTERNS) {
        if (regex.test(lines[i])) {
          hitLines.push(i + 1);
          labels.add(label);
          if (firstContext === undefined) {
            const s = Math.max(0, i - 1);
            const e = Math.min(lines.length, i + 4);
            firstContext = lines.slice(s, e).join("\n");
          }
          break;
        }
      }
    }

    if (hitLines.length === 0) return [];
    const match: CandidateMatch = {
      vulnSlug: "tf-iac-surface",
      lineNumbers: hitLines,
      snippet: firstContext ?? "",
      matchedPattern: Array.from(labels).slice(0, 4).join(", "),
    };
    return [match];
  },
};

import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Storage resources without encryption-at-rest configured. Flags any file
 * that defines an `aws_s3_bucket`, `aws_rds_cluster` / `aws_db_instance`,
 * `aws_ebs_volume`, `aws_dynamodb_table`, `aws_sns_topic`, `aws_sqs_queue`
 * without the matching encryption attribute set in the same file.
 *
 * False-positive prone (encryption may be configured in a sibling file in
 * the same module), so noiseTier = normal and AI review confirms.
 */
export const tfEncryptionMissingMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "tf-encryption-missing",
  description:
    "Terraform storage resource (S3/RDS/EBS/DynamoDB/SNS/SQS) without encryption-at-rest config",
  filePatterns: ["**/*.tf", "**/*.tf.json"],
  requires: { tech: ["terraform"] },
  examples: [
    `resource "aws_s3_bucket" "logs" {\n  bucket = "my-logs"\n}`,
    `resource "aws_db_instance" "db" {\n  engine = "postgres"\n}`,
    `resource "aws_rds_cluster" "main" {\n  engine = "aurora-postgresql"\n}`,
    `resource "aws_ebs_volume" "data" {\n  size = 100\n}`,
    `resource "aws_dynamodb_table" "users" {\n  name = "users"\n  hash_key = "id"\n}`,
    `resource "aws_sns_topic" "alerts" {\n  name = "alerts"\n}`,
    `resource "aws_sqs_queue" "jobs" {\n  name = "jobs"\n}`,
    `resource "aws_elasticache_replication_group" "cache" {\n  replication_group_id = "cache"\n}`,
  ],
  match(content) {
    const lines = content.split("\n");
    const hitLines: number[] = [];
    const labels = new Set<string>();
    let firstContext: string | undefined;

    const RESOURCES: { regex: RegExp; encAttr: RegExp; label: string }[] = [
      // S3 bucket: needs aws_s3_bucket_server_side_encryption_configuration in file or sse block
      {
        regex: /^\s*resource\s+"aws_s3_bucket"\s+/i,
        encAttr:
          /aws_s3_bucket_server_side_encryption_configuration|server_side_encryption_configuration\s*\{/i,
        label: "S3 bucket",
      },
      // RDS / Aurora
      {
        regex: /^\s*resource\s+"aws_(?:rds_cluster|db_instance|db_cluster)"\s+/i,
        encAttr: /\bstorage_encrypted\s*=\s*true\b/i,
        label: "RDS/Aurora",
      },
      // EBS volume
      {
        regex: /^\s*resource\s+"aws_ebs_volume"\s+/i,
        encAttr: /\bencrypted\s*=\s*true\b/i,
        label: "EBS volume",
      },
      // EBS in launch template / launch configuration block_device_mappings
      // (skip — too noisy at file level)
      // DynamoDB
      {
        regex: /^\s*resource\s+"aws_dynamodb_table"\s+/i,
        encAttr: /\bserver_side_encryption\s*\{[^}]*enabled\s*=\s*true/is,
        label: "DynamoDB",
      },
      // SNS
      {
        regex: /^\s*resource\s+"aws_sns_topic"\s+/i,
        encAttr: /\bkms_master_key_id\s*=/i,
        label: "SNS topic",
      },
      // SQS
      {
        regex: /^\s*resource\s+"aws_sqs_queue"\s+/i,
        encAttr: /\bkms_master_key_id\s*=|\bsqs_managed_sse_enabled\s*=\s*true/i,
        label: "SQS queue",
      },
      // ElastiCache redis
      {
        regex: /^\s*resource\s+"aws_elasticache_replication_group"\s+/i,
        encAttr: /\bat_rest_encryption_enabled\s*=\s*true/i,
        label: "ElastiCache",
      },
    ];

    for (let i = 0; i < lines.length; i++) {
      for (const { regex, encAttr, label } of RESOURCES) {
        if (!regex.test(lines[i])) continue;
        // Check whole file (encryption may be set deep in the resource block or in a sibling)
        if (encAttr.test(content)) continue;
        hitLines.push(i + 1);
        labels.add(`${label} without encryption`);
        if (firstContext === undefined) {
          const s = Math.max(0, i - 1);
          const e = Math.min(lines.length, i + 6);
          firstContext = lines.slice(s, e).join("\n");
        }
        break;
      }
    }

    if (hitLines.length === 0) return [];
    const match: CandidateMatch = {
      vulnSlug: "tf-encryption-missing",
      lineNumbers: hitLines,
      snippet: firstContext ?? "",
      matchedPattern: Array.from(labels).slice(0, 4).join(", "),
    };
    return [match];
  },
};

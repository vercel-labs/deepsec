import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Flags `FROM <image>:<tag>` lines that aren't pinned to an immutable digest
 * (`@sha256:…`). Mutable tags re-float at the registry's discretion, so a
 * poisoned upstream tag silently enters your build.
 */
export const dockerfileFromMutableTagMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "dockerfile-from-mutable-tag",
  description: "FROM line uses a mutable tag (no @sha256 digest pin)",
  filePatterns: ["**/Dockerfile", "**/Dockerfile.*", "**/*.Dockerfile"],
  requires: { tech: ["docker"] },
  examples: [
    `FROM node:20`,
    `FROM python:3.11-slim`,
    `FROM ubuntu:22.04`,
    `FROM alpine`,
    `FROM debian:bookworm AS builder`,
    `FROM --platform=linux/amd64 golang:1.21`,
  ],
  match(content) {
    const lines = content.split("\n");
    const hitLines: number[] = [];
    const snippets: string[] = [];

    // Literal tags that have no digest risk by definition
    const OK_BASES = new Set(["scratch"]);

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const m = line.match(/^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+\S+)?\s*$/i);
      if (!m) continue;
      const image = m[1];
      if (image.startsWith("$")) continue; // FROM $ARG — arg-controlled; skip
      if (OK_BASES.has(image)) continue;
      if (image.includes("@sha256:")) continue; // pinned
      // No tag and no digest = ':latest' (still mutable)
      hitLines.push(i + 1);
      const start = Math.max(0, i - 1);
      const end = Math.min(lines.length, i + 2);
      snippets.push(lines.slice(start, end).join("\n"));
    }

    if (hitLines.length === 0) return [];
    const match: CandidateMatch = {
      vulnSlug: "dockerfile-from-mutable-tag",
      lineNumbers: hitLines,
      snippet: snippets[0],
      matchedPattern: "FROM without @sha256 digest",
    };
    return [match];
  },
};

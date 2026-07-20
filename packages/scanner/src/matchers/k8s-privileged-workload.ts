import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

const WORKLOAD_KINDS = new Set([
  "CronJob",
  "DaemonSet",
  "Deployment",
  "DeploymentConfig",
  "Job",
  "Pod",
  "PodTemplate",
  "ReplicaSet",
  "ReplicationController",
  "Rollout",
  "StatefulSet",
]);

const PATTERNS = [
  { regex: /^\s*privileged\s*:\s*true\s*(?:#.*)?$/, label: "privileged container" },
  {
    regex: /^\s*allowPrivilegeEscalation\s*:\s*true\s*(?:#.*)?$/,
    label: "privilege escalation allowed",
  },
  {
    regex: /^\s*host(?:IPC|Network|PID)\s*:\s*true\s*(?:#.*)?$/,
    label: "host namespace shared",
  },
  { regex: /^\s*runAsUser\s*:\s*0\s*(?:#.*)?$/, label: "container runs as root UID" },
  { regex: /^\s*-?\s*hostPath\s*:/, label: "host filesystem mount" },
  { regex: /^\s*procMount\s*:\s*["']?Unmasked["']?\s*$/, label: "unmasked proc mount" },
];

const MATCH_ORDER = new Map(
  [...PATTERNS.map(({ label }) => label), "dangerous Linux capability"].map((label, index) => [
    label,
    index,
  ]),
);

function leadingIndent(line: string): number {
  return line.match(/^\s*/)?.[0].length ?? 0;
}

function isStructuralLine(line: string): boolean {
  return Boolean(line.trim()) && !/^\s*(?:#|{{.*}}\s*$)/.test(line);
}

function topLevelIndent(lines: string[]): number | undefined {
  const structuralLines = lines.filter(isStructuralLine);
  if (structuralLines.length === 0) return undefined;
  return Math.min(...structuralLines.map(leadingIndent));
}

function isWorkloadDocument(lines: string[]): boolean {
  const rootIndent = topLevelIndent(lines);
  if (rootIndent === undefined) return false;
  const topLevel = lines.filter(
    (line) => isStructuralLine(line) && leadingIndent(line) === rootIndent,
  );
  if (!topLevel.some((line) => /^\s*apiVersion\s*:/.test(line))) return false;

  const kindLine = topLevel.find((line) => /^\s*kind\s*:/.test(line));
  const kind = kindLine?.match(/^\s*kind\s*:\s*["']?([^\s"'#]+)["']?\s*(?:#.*)?$/)?.[1];
  return kind !== undefined && WORKLOAD_KINDS.has(kind);
}

function workloadSpecLines(lines: string[]): string[] {
  const rootIndent = topLevelIndent(lines);
  if (rootIndent === undefined) return lines.map(() => "");

  const specIndex = lines.findIndex(
    (line) => leadingIndent(line) === rootIndent && /^\s*spec\s*:/.test(line),
  );
  if (specIndex === -1) return lines.map(() => "");

  let inSpec = true;
  return lines.map((line, index) => {
    if (index < specIndex || !inSpec) return "";
    if (index === specIndex || !isStructuralLine(line)) return line;
    if (leadingIndent(line) <= rootIndent) {
      inSpec = false;
      return "";
    }
    return line;
  });
}

function withoutBlockScalarContent(lines: string[]): string[] {
  let scalarIndent: number | undefined;
  return lines.map((line) => {
    if (scalarIndent !== undefined) {
      if (!line.trim() || leadingIndent(line) > scalarIndent) return "";
      scalarIndent = undefined;
    }
    if (/:\s*[|>](?:[1-9][+-]?|[+-][1-9]?)?\s*(?:#.*)?$/.test(line)) {
      scalarIndent = leadingIndent(line);
    }
    return line;
  });
}

function workloadDocuments(content: string): Array<{ lines: string[]; lineOffset: number }> {
  const lines = content.split("\n");
  const documents: Array<{ lines: string[]; lineOffset: number }> = [];
  let start = 0;

  for (let i = 0; i < lines.length; i++) {
    if (!/^---(?:\s+#.*)?\s*$/.test(lines[i])) continue;
    const documentLines = lines.slice(start, i);
    if (isWorkloadDocument(documentLines)) {
      documents.push({ lines: documentLines, lineOffset: start });
    }
    start = i + 1;
  }

  const documentLines = lines.slice(start);
  if (isWorkloadDocument(documentLines)) {
    documents.push({ lines: documentLines, lineOffset: start });
  }
  return documents;
}

function parentIsCapabilities(lines: string[], lineIndex: number, indent: number): boolean {
  for (let i = lineIndex - 1; i >= 0; i--) {
    if (!lines[i].trim() || /^\s*#/.test(lines[i])) continue;
    if (leadingIndent(lines[i]) >= indent) continue;
    return /^\s*capabilities\s*:\s*(?:#.*)?$/.test(lines[i]);
  }
  return false;
}

function dangerousCapabilityMatch(lines: string[]): CandidateMatch | undefined {
  const dangerous = /(?:^|[,\s["'])(?:ALL|NET_ADMIN|SYS_ADMIN|SYS_PTRACE)(?=$|[,\s\]"'])/;
  const hitLines: number[] = [];
  let firstContext: string | undefined;

  for (let i = 0; i < lines.length; i++) {
    const add = lines[i].match(/^(\s*)add\s*:\s*(.*)$/);
    if (!add || !parentIsCapabilities(lines, i, add[1].length)) continue;

    const inline = add[2].trim();
    if (inline.startsWith("[") && dangerous.test(inline)) {
      hitLines.push(i + 1);
    } else if (!inline || inline.startsWith("#")) {
      for (let j = i + 1; j < lines.length; j++) {
        if (!lines[j].trim() || /^\s*#/.test(lines[j])) continue;
        const indent = leadingIndent(lines[j]);
        const isSequenceEntry = /^\s*-/.test(lines[j]);
        if (indent < add[1].length) break;
        if (indent === add[1].length && !isSequenceEntry) break;
        if (/^\s*-\s*["']?(?:ALL|NET_ADMIN|SYS_ADMIN|SYS_PTRACE)["']?\s*(?:#.*)?$/.test(lines[j])) {
          hitLines.push(j + 1);
        }
      }
    }

    if (firstContext === undefined && hitLines.length > 0) {
      const firstHit = hitLines[0] - 1;
      firstContext = lines.slice(Math.max(0, firstHit - 2), firstHit + 3).join("\n");
    }
  }

  if (hitLines.length === 0) return undefined;
  return {
    vulnSlug: "k8s-privileged-workload",
    lineNumbers: hitLines,
    snippet: firstContext ?? "",
    matchedPattern: "dangerous Linux capability",
  };
}

function mergeMatch(
  matches: Map<string, CandidateMatch>,
  match: CandidateMatch,
  lineOffset: number,
): void {
  const adjustedLines = match.lineNumbers.map((line) => line + lineOffset);
  const existing = matches.get(match.matchedPattern);
  if (existing) {
    existing.lineNumbers.push(...adjustedLines);
    return;
  }
  matches.set(match.matchedPattern, { ...match, lineNumbers: adjustedLines });
}

export const k8sPrivilegedWorkloadMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "k8s-privileged-workload",
  description:
    "Kubernetes workload enabling privileged execution, host access, or dangerous capabilities",
  filePatterns: ["**/*.yaml", "**/*.yml"],
  examples: [
    `apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - securityContext:\n        privileged: true`,
    `apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      hostNetwork: true`,
    `apiVersion: v1\nkind: Pod\nspec:\n  hostPID: true`,
    `apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - securityContext:\n        allowPrivilegeEscalation: true`,
    `apiVersion: v1\nkind: Pod\nspec:\n  securityContext:\n    runAsUser: 0`,
    `apiVersion: v1\nkind: Pod\nspec:\n  volumes:\n    - hostPath:\n        path: /`,
    `apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - securityContext:\n        procMount: Unmasked`,
    `apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - securityContext:\n        capabilities:\n          add: ["SYS_ADMIN"]`,
    `apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - securityContext:\n        capabilities:\n          add:\n            - NET_ADMIN`,
  ],
  match(content, filePath) {
    if (/(?:^|\/)(?:node_modules|vendor|\.github)\//.test(filePath)) return [];

    const matches = new Map<string, CandidateMatch>();
    for (const document of workloadDocuments(content)) {
      const scanLines = withoutBlockScalarContent(workloadSpecLines(document.lines));
      const documentContent = scanLines.join("\n");
      for (const match of regexMatcher("k8s-privileged-workload", PATTERNS, documentContent)) {
        mergeMatch(matches, match, document.lineOffset);
      }
      const capabilityMatch = dangerousCapabilityMatch(scanLines);
      if (capabilityMatch) mergeMatch(matches, capabilityMatch, document.lineOffset);
    }

    return [...matches.values()].sort(
      (a, b) => MATCH_ORDER.get(a.matchedPattern)! - MATCH_ORDER.get(b.matchedPattern)!,
    );
  },
};

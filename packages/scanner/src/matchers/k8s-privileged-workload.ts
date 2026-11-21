import type { CandidateMatch } from "@deepsec/core";
import type { Alias, Document, Node } from "yaml";
import { isAlias, isMap, isScalar, isSeq, LineCounter, parseAllDocuments } from "yaml";
import type { MatcherPlugin } from "../types.js";

const WORKLOAD_API_GROUPS = new Map<string, readonly string[]>([
  ["CronJob", ["batch"]],
  ["DaemonSet", ["apps", "extensions"]],
  ["Deployment", ["apps", "extensions"]],
  ["DeploymentConfig", ["apps.openshift.io"]],
  ["Job", ["batch"]],
  ["Pod", [""]],
  ["PodTemplate", [""]],
  ["ReplicaSet", ["apps", "extensions"]],
  ["ReplicationController", [""]],
  ["Rollout", ["argoproj.io"]],
  ["StatefulSet", ["apps"]],
]);

function apiGroup(version: unknown): string | undefined {
  if (typeof version !== "string") return undefined;
  const match = /^(?:([^/]+)\/)?v\d+(?:(?:alpha|beta)\d+)?$/.exec(version);
  return match ? (match[1] ?? "") : undefined;
}

const LABELS = [
  "privileged container",
  "privilege escalation allowed",
  "host namespace shared",
  "Windows host process container",
  "container runs as root UID",
  "host filesystem mount",
  "unmasked proc mount",
  "dangerous Linux capability",
];
const DANGEROUS_CAPABILITIES = new Set([
  "ALL",
  "AUDIT_CONTROL",
  "BPF",
  "CHECKPOINT_RESTORE",
  "DAC_READ_SEARCH",
  "IPC_OWNER",
  "NET_ADMIN",
  "PERFMON",
  "SYS_ADMIN",
  "SYS_BOOT",
  "SYS_MODULE",
  "SYS_PTRACE",
  "SYS_RAWIO",
  "SYS_RESOURCE",
  "SYS_TIME",
]);
const MAX_DOCUMENT_LENGTH = 1024 * 1024;
const MAX_CONTENT_LENGTH = 16 * MAX_DOCUMENT_LENGTH;
const MAX_LOCATIONS = 64;
const MAX_WORKLOADS = 100_000;

// Resolve aliases once in source order without expanding their object graphs.
function aliasTargets(document: Document): WeakMap<Alias, Node> {
  const targets = new WeakMap<Alias, Node>();
  const anchors = new Map<string, Node>();
  const pending: unknown[] = [document.contents];
  let examined = 0;
  while (pending.length && examined++ < 1_000_000) {
    const node = pending.pop();
    if (isAlias(node)) {
      const target = anchors.get(node.source);
      if (target) targets.set(node, target);
    } else if (isMap(node) || isSeq(node) || isScalar(node)) {
      if (node.anchor) anchors.set(node.anchor, node);
      if (isMap(node)) {
        for (let i = node.items.length - 1; i >= 0; i--) {
          pending.push(node.items[i].value, node.items[i].key);
        }
      } else if (isSeq(node)) {
        for (let i = node.items.length - 1; i >= 0; i--) pending.push(node.items[i]);
      }
    }
  }
  return targets;
}

function resolve(node: unknown, targets: WeakMap<Alias, Node>): Node | undefined {
  if (isAlias(node)) return targets.get(node);
  return isMap(node) || isSeq(node) || isScalar(node) ? node : undefined;
}

// Explicit keys win over `<<` merges; earlier merge sources win over later ones.
function fieldLookup(targets: WeakMap<Alias, Node>) {
  const indexes = new WeakMap<
    Node,
    { explicit: Map<unknown, Node | undefined>; merges: unknown[] }
  >();
  const results = new WeakMap<Node, Map<string, Node | undefined>>();
  let remaining = 1_000_000;
  return (node: unknown, key: string): Node | undefined => {
    const root = resolve(node, targets);
    if (!isMap(root)) return undefined;
    const cached = results.get(root);
    if (cached?.has(key)) return cached.get(key);
    const pending: unknown[] = [root];
    const seen = new Set<Node>();
    let found: Node | undefined;
    while (pending.length && remaining-- > 0) {
      const map = resolve(pending.pop(), targets);
      if (!isMap(map) || seen.has(map)) continue;
      seen.add(map);
      let index = indexes.get(map);
      if (!index) {
        index = { explicit: new Map(), merges: [] };
        for (const entry of map.items) {
          if (remaining-- <= 0) return undefined;
          if (!isScalar(entry.key)) continue;
          if (typeof entry.key.value === "symbol") {
            const sources = resolve(entry.value, targets);
            for (const source of isSeq(sources) ? sources.items : [sources]) {
              if (remaining-- <= 0) return undefined;
              index.merges.push(source);
            }
          } else index.explicit.set(entry.key.value, resolve(entry.value, targets));
        }
        indexes.set(map, index);
      }
      if (index.explicit.has(key)) {
        found = index.explicit.get(key);
        break;
      }
      for (let i = index.merges.length - 1; i >= 0; i--) pending.push(index.merges[i]);
    }
    const cache = cached ?? new Map<string, Node | undefined>();
    cache.set(key, found);
    results.set(root, cache);
    return found;
  };
}

// Preserve source offsets while masking Go actions, including strings and block comments.
function maskTemplates(content: string): string | undefined {
  if (!content.includes("{{")) return content;
  const blanks: string[] = [];
  const actions: { open: number; end: number; line: number; endLine: number; comment: boolean }[] =
    [];
  let start = 0;
  let line = 0;
  let remaining = 2 * content.length;
  let examined = 0;
  while (start < content.length) {
    const open = content.indexOf("{{", start);
    if (open === -1) break;
    if (examined++ >= 100_000 || remaining <= 0) return undefined;
    const before = content.slice(start, open);
    blanks.push(before);
    line += before.split("\n").length - 1;
    let end = open + 2;
    let quote = "";
    let comment = false;
    const limit = Math.min(content.length, open + 65_536);
    let firstToken = end + Number(content[end] === "-");
    while (firstToken < limit && /\s/.test(content[firstToken])) firstToken++;
    const commentAction = content.startsWith("/*", firstToken);
    let closed = false;
    while (end < limit && remaining-- > 0) {
      if (comment) {
        if (content.startsWith("*/", end)) {
          comment = false;
          end += 2;
        } else end++;
      } else if (quote) {
        if (content[end] === "\\" && quote !== "`") end += 2;
        else if (content[end++] === quote) quote = "";
      } else if (content.startsWith("{{", end)) {
        break;
      } else if (content.startsWith("/*", end)) {
        comment = true;
        end += 2;
      } else if (content.startsWith("}}", end)) {
        end += 2;
        closed = true;
        break;
      } else if ("\"'`".includes(content[end])) quote = content[end++];
      else end++;
    }
    if (!closed) {
      blanks.push("{{");
      start = open + 2;
      continue;
    }
    end = Math.min(end, content.length);
    const action = content.slice(open, end);
    const endLine = line + action.split("\n").length - 1;
    actions.push({ open, end, line, endLine, comment: commentAction });
    blanks.push(action.replace(/[^\r\n]/g, " "));
    start = end;
    line = endLine;
  }
  blanks.push(content.slice(start));
  const staticLines = blanks
    .join("")
    .split("\n")
    .map((text) => Boolean(text.trim()));
  const output: string[] = [];
  start = 0;
  for (const action of actions) {
    output.push(content.slice(start, action.open));
    const inline = !action.comment && (staticLines[action.line] || staticLines[action.endLine]);
    let firstLine = true;
    output.push(
      content.slice(action.open, action.end).replace(/[\s\S]/g, (char) => {
        if (char === "\r" || char === "\n") {
          firstLine = false;
          return char;
        }
        return inline && firstLine ? "_" : " ";
      }),
    );
    start = action.end;
  }
  output.push(content.slice(start));
  return output.join("");
}

// Split at document markers so one oversized document doesn't hide the rest of a bundle.
function documentChunks(content: string): { text: string; line: number }[] {
  const chunks: { text: string; line: number }[] = [];
  const lines = content.split("\n");
  let start = 0;
  for (let i = 1; i <= lines.length; i++) {
    if (i === lines.length || /^---(?:\s|$)/.test(lines[i])) {
      const text = lines.slice(start, i).join("\n");
      if (text.length <= MAX_DOCUMENT_LENGTH) chunks.push({ text, line: start });
      start = i;
    }
  }
  return chunks;
}

function scalar(node: unknown): unknown {
  return isScalar(node) ? node.value : undefined;
}

export const k8sPrivilegedWorkloadMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "k8s-privileged-workload",
  description:
    "Kubernetes workload enabling privileged execution, host access, or dangerous capabilities",
  filePatterns: ["**/*.yaml", "**/*.yml", "**/*.json"],
  examples: [
    `apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - securityContext:\n        privileged: true`,
    `apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - securityContext: {privileged: true}`,
    `apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      hostNetwork: true`,
    `apiVersion: v1\nkind: Pod\nspec:\n  hostPID: true`,
    `{apiVersion: v1, kind: Pod, spec: {hostIPC: true}}`,
    `apiVersion: v1\nkind: PodTemplate\ntemplate:\n  spec:\n    hostNetwork: true`,
    `apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - securityContext:\n        allowPrivilegeEscalation: true`,
    `apiVersion: v1\nkind: Pod\nspec:\n  securityContext:\n    windowsOptions:\n      hostProcess: true`,
    `apiVersion: v1\nkind: Pod\nspec:\n  securityContext:\n    runAsUser: 0`,
    `apiVersion: v1\nkind: Pod\nspec:\n  volumes:\n    - hostPath:\n        path: /`,
    `apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - securityContext:\n        procMount: Unmasked`,
    `apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - securityContext:\n        capabilities:\n          add: ["SYS_ADMIN"]`,
    `apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - securityContext:\n        capabilities:\n          add:\n            - SYS_MODULE`,
  ],
  match(content, filePath) {
    if (/(?:^|\/)(?:node_modules|vendor|charts\/[^/]+\/charts)\//.test(filePath)) return [];
    if (content.length > MAX_CONTENT_LENGTH) return [];

    const masked = maskTemplates(content);
    if (masked === undefined) return [];
    const hits = new Map<string, Set<number>>();
    for (const chunk of documentChunks(masked)) {
      const lineCounter = new LineCounter();
      let documents: Document[];
      try {
        // Kubernetes uses YAML 1.1 scalars, including yes/on and alternative integer spellings.
        documents = parseAllDocuments(chunk.text, {
          version: "1.1",
          lineCounter,
          prettyErrors: false,
          uniqueKeys: false,
        });
      } catch {
        continue;
      }
      const record = (label: string, node: Node) => {
        let locations = hits.get(label);
        if (!locations) {
          locations = new Set();
          hits.set(label, locations);
        }
        if (locations.size < MAX_LOCATIONS && node.range)
          locations.add(chunk.line + lineCounter.linePos(node.range[0]).line);
      };
      for (const document of documents) {
        if (document.errors.length) continue;
        const targets = aliasTargets(document);
        const get = fieldLookup(targets);
        const check = (node: unknown, key: string, value: unknown, label: string) => {
          const found = get(node, key);
          if (found && scalar(found) === value) record(label, found);
        };
        const securityContext = (node: unknown) => {
          check(node, "privileged", true, LABELS[0]);
          check(node, "allowPrivilegeEscalation", true, LABELS[1]);
          check(get(node, "windowsOptions"), "hostProcess", true, LABELS[3]);
          check(node, "runAsUser", 0, LABELS[4]);
          check(node, "procMount", "Unmasked", LABELS[6]);
          const add = get(get(node, "capabilities"), "add");
          if (isSeq(add)) {
            for (const item of add.items) {
              const value = resolve(item, targets);
              if (value && DANGEROUS_CAPABILITIES.has(String(scalar(value))))
                record(LABELS[7], value);
            }
          }
        };
        const pending: { node: unknown; inheritedKind?: string; inheritedApiVersion?: string }[] = [
          { node: document.contents },
        ];
        const visited = new Set<Node>();
        let examined = 0;
        while (pending.length && examined++ < MAX_WORKLOADS) {
          const { node, inheritedKind, inheritedApiVersion } = pending.pop()!;
          const resource = resolve(node, targets);
          if (!resource || visited.has(resource)) continue;
          visited.add(resource);
          const kind = scalar(get(resource, "kind")) ?? inheritedKind;
          if (typeof kind !== "string") continue;
          const version = scalar(get(resource, "apiVersion")) ?? inheritedApiVersion;
          const group = apiGroup(version);
          if (group === undefined) continue;
          if (kind.endsWith("List")) {
            const itemKind = kind.slice(0, -4) || undefined;
            if (itemKind ? !WORKLOAD_API_GROUPS.get(itemKind)?.includes(group) : group !== "")
              continue;
            const items = get(resource, "items");
            if (isSeq(items)) {
              for (let i = items.items.length - 1; i >= 0 && pending.length < MAX_WORKLOADS; i--) {
                pending.push({
                  node: items.items[i],
                  inheritedKind: itemKind,
                  inheritedApiVersion: itemKind ? String(version) : undefined,
                });
              }
            }
            continue;
          }
          if (!WORKLOAD_API_GROUPS.get(kind)?.includes(group)) continue;
          let spec = get(resource, "spec");
          if (kind === "PodTemplate") spec = get(get(resource, "template"), "spec");
          else if (kind === "CronJob")
            spec = get(get(get(get(spec, "jobTemplate"), "spec"), "template"), "spec");
          else if (kind !== "Pod") spec = get(get(spec, "template"), "spec");
          for (const key of ["hostIPC", "hostNetwork", "hostPID"])
            check(spec, key, true, LABELS[2]);
          securityContext(get(spec, "securityContext"));
          for (const key of ["containers", "initContainers", "ephemeralContainers"]) {
            const containers = get(spec, key);
            if (isSeq(containers))
              for (const container of containers.items)
                securityContext(get(container, "securityContext"));
          }
          const volumes = get(spec, "volumes");
          if (isSeq(volumes)) {
            for (const volume of volumes.items) {
              const hostPath = get(volume, "hostPath");
              if (isMap(hostPath)) record(LABELS[5], hostPath);
            }
          }
        }
      }
    }
    const lines = content.split("\n");
    return LABELS.flatMap((label): CandidateMatch[] => {
      const locations = hits.get(label);
      if (!locations?.size) return [];
      const lineNumbers = [...locations].sort((a, b) => a - b);
      const first = lineNumbers[0];
      return [
        {
          vulnSlug: "k8s-privileged-workload",
          lineNumbers,
          snippet: lines
            .slice(Math.max(0, first - 3), first + 2)
            .join("\n")
            .slice(0, 2048),
          matchedPattern: label,
        },
      ];
    });
  },
};

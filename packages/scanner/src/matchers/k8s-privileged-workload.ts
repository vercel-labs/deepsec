import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

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
  ],
  match(content, filePath) {
    if (/(?:^|\/)(?:node_modules|vendor|charts|\.github)\//.test(filePath)) return [];
    if (!/^\s*apiVersion\s*:/m.test(content) || !/^\s*kind\s*:/m.test(content)) return [];

    return regexMatcher(
      "k8s-privileged-workload",
      [
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
        {
          regex: /^\s*add\s*:\s*\[[^\]]*["']?(?:ALL|NET_ADMIN|SYS_ADMIN|SYS_PTRACE)["']?[^\]]*\]/,
          label: "dangerous Linux capability",
        },
      ],
      content,
    );
  },
};

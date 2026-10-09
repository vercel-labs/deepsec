import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { authBypassMatcher } from "../matchers/auth-bypass.js";
import { insecureCryptoMatcher } from "../matchers/insecure-crypto.js";
import { k8sPrivilegedWorkloadMatcher } from "../matchers/k8s-privileged-workload.js";
import { missingAuthMatcher } from "../matchers/missing-auth.js";
import { openRedirectMatcher } from "../matchers/open-redirect.js";
import { pathTraversalMatcher } from "../matchers/path-traversal.js";
import { rceMatcher } from "../matchers/rce.js";
import { secretsExposureMatcher } from "../matchers/secrets-exposure.js";
import { sqlInjectionMatcher } from "../matchers/sql-injection.js";
import { ssrfMatcher } from "../matchers/ssrf.js";
import { xssMatcher } from "../matchers/xss.js";

const FIXTURES_ROOT = path.resolve(import.meta.dirname, "../../../../fixtures/vulnerable-app/src");

function readFixture(relativePath: string): string {
  return fs.readFileSync(path.join(FIXTURES_ROOT, relativePath), "utf-8");
}

describe("auth-bypass matcher", () => {
  it("detects auth patterns in admin.ts", () => {
    const content = readFixture("api/admin.ts");
    const matches = authBypassMatcher.match(content, "src/api/admin.ts");
    expect(matches.length).toBeGreaterThan(0);
    expect(matches.some((m) => m.vulnSlug === "auth-bypass")).toBe(true);
  });
});

describe("missing-auth matcher", () => {
  it("flags all HTTP entry points in users.ts as weak candidates", () => {
    const content = readFixture("api/users.ts");
    const matches = missingAuthMatcher.match(content, "src/api/users.ts");
    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0].vulnSlug).toBe("missing-auth");
    expect(matches[0].matchedPattern).toContain("weak candidate");
  });

  it("also flags admin.ts — all entry points are candidates", () => {
    const content = readFixture("api/admin.ts");
    const matches = missingAuthMatcher.match(content, "src/api/admin.ts");
    // Now flags all entry points regardless of auth presence
    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0].matchedPattern).toContain("weak candidate");
  });

  it("does not flag non-handler files", () => {
    const content = readFixture("lib/db.ts");
    const matches = missingAuthMatcher.match(content, "src/lib/db.ts");
    expect(matches.length).toBe(0);
  });
});

describe("xss matcher", () => {
  it("detects dangerouslySetInnerHTML", () => {
    const content = readFixture("components/comment.tsx");
    const matches = xssMatcher.match(content, "src/components/comment.tsx");
    expect(matches.length).toBeGreaterThan(0);
    const slugs = matches.map((m) => m.matchedPattern);
    expect(slugs).toContain("dangerouslySetInnerHTML");
  });
});

describe("rce matcher", () => {
  it("detects exec/eval patterns", () => {
    const content = readFixture("utils/exec-helper.ts");
    const matches = rceMatcher.match(content, "src/utils/exec-helper.ts");
    expect(matches.length).toBeGreaterThan(0);
    const patterns = matches.map((m) => m.matchedPattern);
    expect(patterns.some((p) => p.includes("exec") || p.includes("eval"))).toBe(true);
  });
});

describe("sql-injection matcher", () => {
  it("detects interpolated SQL", () => {
    const content = readFixture("lib/db.ts");
    const matches = sqlInjectionMatcher.match(content, "src/lib/db.ts");
    expect(matches.length).toBeGreaterThan(0);
  });
});

describe("ssrf matcher", () => {
  it("detects fetch with user-controlled URL", () => {
    const content = readFixture("lib/fetch-proxy.ts");
    const matches = ssrfMatcher.match(content, "src/lib/fetch-proxy.ts");
    expect(matches.length).toBeGreaterThan(0);
  });
});

describe("path-traversal matcher", () => {
  it("detects file operations with user input", () => {
    const content = readFixture("api/upload.ts");
    const matches = pathTraversalMatcher.match(content, "src/api/upload.ts");
    expect(matches.length).toBeGreaterThan(0);
  });
});

describe("secrets-exposure matcher", () => {
  it("detects hardcoded secrets", () => {
    const content = readFixture("config.ts");
    const matches = secretsExposureMatcher.match(content, "src/config.ts");
    expect(matches.length).toBeGreaterThan(0);
  });
});

describe("insecure-crypto matcher", () => {
  it("detects MD5 and Math.random", () => {
    const content = readFixture("lib/crypto.ts");
    const matches = insecureCryptoMatcher.match(content, "src/lib/crypto.ts");
    expect(matches.length).toBeGreaterThan(0);
    const patterns = matches.map((m) => m.matchedPattern);
    expect(patterns.some((p) => p.includes("MD5"))).toBe(true);
    expect(patterns.some((p) => p.includes("Math.random"))).toBe(true);
  });
});

describe("open-redirect matcher", () => {
  it("detects redirect with user input", () => {
    const content = readFixture("utils/redirect.ts");
    const matches = openRedirectMatcher.match(content, "src/utils/redirect.ts");
    expect(matches.length).toBeGreaterThan(0);
  });
});

describe("k8s-privileged-workload matcher", () => {
  it("detects privileged Kubernetes workload settings", () => {
    const content = `apiVersion: v1
kind: Pod
spec:
  hostPID: true
  containers:
    - securityContext:
        privileged: true
        allowPrivilegeEscalation: true`;
    const matches = k8sPrivilegedWorkloadMatcher.match(content, "deploy/pod.yaml");
    expect(matches.map((match) => match.matchedPattern)).toEqual([
      "privileged container",
      "privilege escalation allowed",
      "host namespace shared",
    ]);
  });

  it("detects settings written as inline flow maps", () => {
    const content = `apiVersion: v1
kind: Pod
spec: {hostNetwork: true}
---
apiVersion: v1
kind: Pod
spec:
  containers:
    - securityContext: {privileged: true, capabilities: {drop: [ALL], add: [SYS_ADMIN]}}
    - {name: sidecar, securityContext: {privileged: false, capabilities: {add: [CHOWN]}}}`;
    const matches = k8sPrivilegedWorkloadMatcher.match(content, "deploy/pod.yaml");
    expect(matches.map((match) => [match.matchedPattern, match.lineNumbers])).toEqual([
      ["privileged container", [9]],
      ["host namespace shared", [3]],
      ["dangerous Linux capability", [9]],
    ]);
  });

  it("detects Windows host process containers", () => {
    const content = `apiVersion: v1
kind: Pod
spec:
  securityContext:
    windowsOptions:
      hostProcess: true`;
    const matches = k8sPrivilegedWorkloadMatcher.match(content, "deploy/pod.yaml");
    expect(matches.map((match) => match.matchedPattern)).toEqual([
      "Windows host process container",
    ]);
  });

  it("detects workloads inside a List", () => {
    const content = `apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: ConfigMap
    data:
      privileged: true
  - apiVersion: v1
    kind: Pod
    spec:
      containers:
        - securityContext:
            privileged: true`;
    const matches = k8sPrivilegedWorkloadMatcher.match(content, "deploy/list.yaml");
    expect(matches.map((match) => match.matchedPattern)).toEqual(["privileged container"]);
    expect(matches[0].lineNumbers).toEqual([13]);
  });

  it("does not flag hardened workloads or non-Kubernetes YAML", () => {
    const hardened = `apiVersion: v1
kind: Pod
spec:
  hostPID: false
  containers:
    - securityContext:
        privileged: false
        allowPrivilegeEscalation: false
        runAsNonRoot: true
        capabilities:
          drop: ["ALL"]`;
    expect(k8sPrivilegedWorkloadMatcher.match(hardened, "deploy/pod.yaml")).toEqual([]);
    expect(k8sPrivilegedWorkloadMatcher.match("hostNetwork: true", "config/settings.yaml")).toEqual(
      [],
    );
  });

  it("detects block-list capabilities and first-party Helm charts", () => {
    const content = `apiVersion: v1
kind: Pod
spec:
  containers:
    - securityContext:
        capabilities:
          add:
            - SYS_ADMIN`;
    const matches = k8sPrivilegedWorkloadMatcher.match(content, "charts/app/templates/pod.yaml");
    expect(matches.map((match) => match.matchedPattern)).toEqual(["dangerous Linux capability"]);
    expect(matches[0].lineNumbers).toEqual([8]);
  });

  it("supports indentationless capability sequences without scanning sibling lists", () => {
    const dangerous = `apiVersion: v1
kind: Pod
spec:
  containers:
    - securityContext:
        capabilities:
          add:
          - SYS_ADMIN`;
    const matches = k8sPrivilegedWorkloadMatcher.match(dangerous, "deploy/pod.yaml");
    expect(matches.map((match) => match.matchedPattern)).toEqual(["dangerous Linux capability"]);
    expect(matches[0].lineNumbers).toEqual([8]);

    const dropped = `apiVersion: v1
kind: Pod
spec:
  containers:
    - securityContext:
        capabilities:
          add:
          - CHOWN
          drop:
          - SYS_ADMIN`;
    expect(k8sPrivilegedWorkloadMatcher.match(dropped, "deploy/pod.yaml")).toEqual([]);
  });

  it("ignores non-workload documents and capabilities being dropped", () => {
    const content = `apiVersion: v1
kind: ConfigMap
data:
  settings.yaml: |
    privileged: true
---
apiVersion: v1
kind: Pod
spec:
  containers:
    - securityContext:
        capabilities:
          drop:
            - SYS_ADMIN`;
    expect(k8sPrivilegedWorkloadMatcher.match(content, "deploy/resources.yaml")).toEqual([]);
  });

  it("reports global line numbers from workload documents only", () => {
    const content = `apiVersion: v1
kind: ConfigMap
data:
  privileged: true
---
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      hostNetwork: true`;
    const matches = k8sPrivilegedWorkloadMatcher.match(content, "deploy/resources.yaml");
    expect(matches.map((match) => match.matchedPattern)).toEqual(["host namespace shared"]);
    expect(matches[0].lineNumbers).toEqual([11]);
  });

  it("does not split a document on an indented YAML block scalar", () => {
    const content = `apiVersion: v1
kind: Pod
metadata:
  annotations:
    example.com/config: |
      ---
      nested: content
spec:
  hostPID: true`;
    const matches = k8sPrivilegedWorkloadMatcher.match(content, "deploy/pod.yaml");
    expect(matches.map((match) => match.matchedPattern)).toEqual(["host namespace shared"]);
    expect(matches[0].lineNumbers).toEqual([9]);
  });

  it("ignores YAML-looking text outside the workload spec or inside scalar data", () => {
    const content = `apiVersion: v1
kind: Pod
metadata:
  annotations:
    hostPID: true
spec:
  containers:
    - name: app
      env:
        - name: CONFIG
          value: |
            privileged: true
            capabilities:
              add:
                - SYS_ADMIN`;
    expect(k8sPrivilegedWorkloadMatcher.match(content, "deploy/pod.yaml")).toEqual([]);
  });

  it("skips manifests beyond the parser input budget", () => {
    const containers = Array.from({ length: 200_000 }, (_, i) => `    - name: c${i}`);
    const content = ["apiVersion: v1", "kind: Pod", "spec:", "  containers:", ...containers]
      .concat("  hostPID: true")
      .join("\n");
    const matches = k8sPrivilegedWorkloadMatcher.match(content, "deploy/pod.yaml");
    expect(matches).toEqual([]);
  });

  it("ignores settings that only appear inside quoted values or comments", () => {
    const content = `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      args: ["--flags", "{privileged: true}"]
      env:
        - {name: A, value: "{privileged: true}"}
        - name: B
          value: '{"hostPID": true}'
        - name: C
          value: plain # {hostNetwork: true}
      # securityContext: {allowPrivilegeEscalation: true}`;
    expect(k8sPrivilegedWorkloadMatcher.match(content, "deploy/pod.yaml")).toEqual([]);
  });

  it("detects flow maps with quoted keys and quoted text before a comment marker", () => {
    const content = `apiVersion: v1
kind: Pod
spec:
  containers:
    - securityContext: {"privileged": true}
    - {name: "a # b", securityContext: {'allowPrivilegeEscalation': true}}
    - securityContext:
        "runAsUser": 0 # root`;
    const matches = k8sPrivilegedWorkloadMatcher.match(content, "deploy/pod.yaml");
    expect(matches.map((match) => [match.matchedPattern, match.lineNumbers])).toEqual([
      ["privileged container", [5]],
      ["privilege escalation allowed", [6]],
      ["container runs as root UID", [8]],
    ]);
  });

  it("ignores pod template labels and annotations", () => {
    const content = `apiVersion: apps/v1
kind: StatefulSet
spec:
  template:
    metadata:
      labels:
        privileged: true
      annotations:
        hostPath: /cache
    spec:
      hostNetwork: true
  volumeClaimTemplates:
    - metadata:
        annotations:
          hostPID: true
      spec:
        accessModes: [ReadWriteOnce]`;
    const matches = k8sPrivilegedWorkloadMatcher.match(content, "deploy/sts.yaml");
    expect(matches.map((match) => [match.matchedPattern, match.lineNumbers])).toEqual([
      ["host namespace shared", [11]],
    ]);
  });

  it("skips Helm dependency charts but scans first-party chart templates", () => {
    const content = `apiVersion: v1
kind: Pod
spec:
  hostPID: true`;
    expect(
      k8sPrivilegedWorkloadMatcher.match(content, "charts/app/charts/redis/templates/pod.yaml"),
    ).toEqual([]);
    expect(
      k8sPrivilegedWorkloadMatcher.match(content, "charts/app/templates/pod.yaml"),
    ).toHaveLength(1);
  });

  it("accepts every YAML 1.1 spelling of true", () => {
    const content = `apiVersion: v1
kind: Pod
spec:
  hostNetwork: TRUE
  hostPID: yes
  hostIPC: n
  containers:
    - securityContext:
        privileged: True
        allowPrivilegeEscalation: on
        windowsOptions: {hostProcess: Y}`;
    const matches = k8sPrivilegedWorkloadMatcher.match(content, "deploy/pod.yaml");
    expect(matches.map((match) => [match.matchedPattern, match.lineNumbers])).toEqual([
      ["privileged container", [9]],
      ["privilege escalation allowed", [10]],
      ["host namespace shared", [4, 5]],
      ["Windows host process container", [11]],
    ]);
  });

  it("ignores quoted true and 0, which are strings such as label values", () => {
    const content = `apiVersion: apps/v1
kind: Deployment
spec:
  selector:
    matchLabels: {hostNetwork: "true"}
  template:
    spec:
      nodeSelector:
        privileged: "true"
        runAsUser: '0'
      containers:
        - securityContext: {privileged: true}`;
    const matches = k8sPrivilegedWorkloadMatcher.match(content, "deploy/app.yaml");
    expect(matches.map((match) => [match.matchedPattern, match.lineNumbers])).toEqual([
      ["privileged container", [12]],
    ]);
  });

  it("detects pod settings in a PodTemplate", () => {
    const content = `apiVersion: v1
kind: PodTemplate
metadata:
  name: node-monitor
template:
  metadata:
    annotations:
      hostPID: true
  spec:
    hostPID: true`;
    const matches = k8sPrivilegedWorkloadMatcher.match(content, "deploy/template.yaml");
    expect(matches.map((match) => [match.matchedPattern, match.lineNumbers])).toEqual([
      ["host namespace shared", [10]],
    ]);
  });

  it("detects workloads inside typed lists", () => {
    const content = `apiVersion: v1
kind: PodList
items:
- metadata:
    name: node-monitor
  spec:
    hostNetwork: true
---
apiVersion: apps/v1
kind: DeploymentList
items:
  - apiVersion: apps/v1
    kind: Deployment
    spec:
      template:
        spec:
          hostIPC: true
---
apiVersion: v1
kind: ServiceList
items:
- spec:
    hostNetwork: true`;
    const matches = k8sPrivilegedWorkloadMatcher.match(content, "deploy/list.yaml");
    expect(matches.map((match) => [match.matchedPattern, match.lineNumbers])).toEqual([
      ["host namespace shared", [7, 17]],
    ]);
  });

  it("detects module loading, raw I/O, DAC bypass, and BPF capabilities", () => {
    for (const capability of ["SYS_MODULE", "SYS_RAWIO", "DAC_READ_SEARCH", "BPF"]) {
      const content = `apiVersion: v1
kind: Pod
spec:
  containers:
    - securityContext:
        capabilities:
          add: [CHOWN, "${capability}"]`;
      const matches = k8sPrivilegedWorkloadMatcher.match(content, "deploy/pod.yaml");
      expect(matches.map((match) => match.matchedPattern)).toEqual(["dangerous Linux capability"]);
    }
  });

  it("builds snippets from the original manifest lines", () => {
    const content = `apiVersion: v1
kind: Pod
spec:
  hostPID: true # node monitor`;
    const [match] = k8sPrivilegedWorkloadMatcher.match(content, "deploy/pod.yaml");
    expect(match.snippet).toBe("kind: Pod\nspec:\n  hostPID: true # node monitor");
  });

  it("detects documents written entirely in flow style", () => {
    const content = `{apiVersion: v1, kind: Pod, metadata: {annotations: {hostPath: /x}}, spec: {hostPID: true}}
---
{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {"annotations": {"privileged": "true"}},
  "spec": {"hostNetwork": true}
}
---
{apiVersion: v1, kind: ConfigMap, data: {privileged: true}}`;
    const matches = k8sPrivilegedWorkloadMatcher.match(content, "deploy/pods.yaml");
    expect(matches.map((match) => [match.matchedPattern, match.lineNumbers])).toEqual([
      ["host namespace shared", [1, 7]],
    ]);
  });
});

describe("k8s privileged workload syntax boundaries", () => {
  it("scans JSON and flow lists with multiline capabilities", () => {
    expect(k8sPrivilegedWorkloadMatcher.filePatterns).toContain("**/*.json");
    const content = JSON.stringify(
      {
        apiVersion: "v1",
        kind: "List",
        items: [
          {
            apiVersion: "v1",
            kind: "Pod",
            spec: {
              containers: [
                {
                  securityContext: {
                    privileged: true,
                    capabilities: { add: ["SYS_ADMIN"] },
                  },
                },
              ],
            },
          },
        ],
      },
      null,
      2,
    );
    expect(
      k8sPrivilegedWorkloadMatcher
        .match(content, "deployment.json")
        .map((hit) => hit.matchedPattern),
    ).toEqual(["privileged container", "dangerous Linux capability"]);
    const flow = "{apiVersion: v1, kind: PodList, items: [{spec: {hostPID: true}}]}";
    expect(
      k8sPrivilegedWorkloadMatcher.match(flow, "pods.yaml").map((hit) => hit.matchedPattern),
    ).toEqual(["host namespace shared"]);
  });

  it("splits commented separators and retains original source lines", () => {
    const content =
      "apiVersion: v1\nkind: ConfigMap\ndata: {}\n--- # generated\napiVersion: v1\nkind: Pod\nspec:\n  hostPID: true";
    expect(k8sPrivilegedWorkloadMatcher.match(content, "pods.yaml")[0].lineNumbers).toEqual([8]);
  });

  it("only detects hostPath in volume definitions", () => {
    const content = `apiVersion: v1
kind: Pod
spec:
  nodeSelector: {hostPath: linux}
  volumes:
    - csi: {driver: example.com, volumeAttributes: {hostPath: linux}}
    - hostPath: {path: /}`;
    expect(
      k8sPrivilegedWorkloadMatcher
        .match(content, "pods.yaml")
        .map((hit) => [hit.matchedPattern, hit.lineNumbers]),
    ).toEqual([["host filesystem mount", [7]]]);
  });

  it.each(["+0", "00", "0x0"])("recognizes YAML root UID %s", (uid) => {
    const content = `apiVersion: v1\nkind: Pod\nspec:\n  securityContext: {runAsUser: ${uid}}`;
    expect(k8sPrivilegedWorkloadMatcher.match(content, "pods.yaml")[0].matchedPattern).toBe(
      "container runs as root UID",
    );
  });

  it("checks CronJob, init and ephemeral container security contexts", () => {
    const content = `apiVersion: batch/v1
kind: CronJob
spec:
  jobTemplate:
    spec:
      template:
        spec:
          initContainers:
            - securityContext: {privileged: true}
          ephemeralContainers:
            - securityContext: {allowPrivilegeEscalation: true}`;
    expect(
      k8sPrivilegedWorkloadMatcher.match(content, "job.yaml").map((hit) => hit.matchedPattern),
    ).toEqual(["privileged container", "privilege escalation allowed"]);
  });

  it("does not interpret arbitrary keys or quoted scalars as pod settings", () => {
    const content = `apiVersion: v1
kind: Pod
metadata: {annotations: {privileged: true}}
spec:
  nodeSelector: {privileged: true, runAsUser: 0}
  containers:
    - env: [{name: X, value: 'privileged: true'}]
      securityContext: {privileged: "true", runAsUser: "0"}`;
    expect(k8sPrivilegedWorkloadMatcher.match(content, "pods.yaml")).toEqual([]);
  });

  it("caps persisted locations and snippets", () => {
    const containers = Array.from(
      { length: 200 },
      () => "    - securityContext: {privileged: true}",
    );
    const content = ["apiVersion: v1", "kind: Pod", "spec:", "  containers:", ...containers].join(
      "\n",
    );
    const [hit] = k8sPrivilegedWorkloadMatcher.match(content, "pods.yaml");
    expect(hit.lineNumbers).toHaveLength(64);
    expect(hit.snippet.length).toBeLessThanOrEqual(2048);
    expect(hit.lineNumbers[0]).toBe(5);
  });

  it("handles repeated add keys without backward or forward scans", () => {
    const content = [
      "apiVersion: v1",
      "kind: Pod",
      "spec:",
      ...Array.from({ length: 20_000 }, (_, i) => `  unrelated${i}: {add: []}`),
    ].join("\n");
    expect(k8sPrivilegedWorkloadMatcher.match(content, "pods.yaml")).toEqual([]);
  });

  it("bounds alias cycles and skips invalid or oversized documents", () => {
    const cycle =
      "apiVersion: v1\nkind: List\nitems: &items [{apiVersion: v1, kind: List, items: *items}]";
    expect(k8sPrivilegedWorkloadMatcher.match(cycle, "pods.yaml")).toEqual([]);
    expect(k8sPrivilegedWorkloadMatcher.match("{invalid", "pods.yaml")).toEqual([]);
    expect(k8sPrivilegedWorkloadMatcher.match(" ".repeat(1024 * 1024 + 1), "pods.yaml")).toEqual(
      [],
    );
  });

  it("skips only the oversized document in a multi-document bundle", () => {
    const big = `apiVersion: v1\nkind: ConfigMap\ndata:\n  blob: "${"x".repeat(1024 * 1024)}"`;
    const pod = "apiVersion: v1\nkind: Pod\nspec:\n  hostPID: true";
    const matches = k8sPrivilegedWorkloadMatcher.match(`${big}\n---\n${pod}`, "bundle.yaml");
    expect(matches.map((match) => [match.matchedPattern, match.lineNumbers])).toEqual([
      ["host namespace shared", [9]],
    ]);
  });

  it("follows YAML merge keys, with explicit keys taking precedence", () => {
    const content = `defaults: &ctx {privileged: true, runAsUser: 0}
extra: &extra {allowPrivilegeEscalation: true, runAsUser: 1000}
apiVersion: v1
kind: Pod
spec:
  containers:
    - securityContext:
        <<: *ctx
        runAsUser: 1000
    - securityContext:
        <<: [*extra, *ctx]
    - securityContext: &self
        <<: *self`;
    const matches = k8sPrivilegedWorkloadMatcher.match(content, "pods.yaml");
    expect(matches.map((match) => [match.matchedPattern, match.lineNumbers])).toEqual([
      ["privileged container", [1]],
      ["privilege escalation allowed", [2]],
    ]);
  });

  it("scans Helm templates that contain Go template actions", () => {
    const content = `{{- if .Values.enabled }}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "app.fullname" . }}
  labels:
    {{- include "app.labels" . | nindent 4 }}
spec:
  template:
    spec:
      containers:
        - image: "{{ .Values.image.repository }}:{{ .Chart.AppVersion }}"
          securityContext:
            privileged: true
            runAsUser: {{ .Values.uid }}
{{- end }}`;
    const matches = k8sPrivilegedWorkloadMatcher.match(
      content,
      "charts/app/templates/deployment.yaml",
    );
    expect(matches.map((match) => [match.matchedPattern, match.lineNumbers])).toEqual([
      ["privileged container", [14]],
    ]);
    expect(matches[0].snippet).toContain("{{ .Values.uid }}");
  });
});

describe("k8s privileged workload aliases", () => {
  it("preserves unmatched literal template openings and scans later documents", () => {
    const content = `apiVersion: v1
kind: ConfigMap
data:
  note: "see {{"
---
apiVersion: v1
kind: Pod
spec: {hostPID: true}`;
    expect(k8sPrivilegedWorkloadMatcher.match(content, "bundle.yaml")[0].lineNumbers).toEqual([8]);
  });

  it("preserves literal openings with unmatched Go quotes before valid Helm actions", () => {
    const content = `apiVersion: v1
kind: Pod
metadata:
  annotations: {note: "{{ don't }}"}
  name: {{ .Values.name }}
spec: {hostPID: true}`;
    expect(k8sPrivilegedWorkloadMatcher.match(content, "pod.yaml")[0].lineNumbers).toEqual([6]);
  });

  it.each([
    "PERFMON",
    "CHECKPOINT_RESTORE",
    "SYS_RESOURCE",
  ])("detects high-impact capability %s only when added", (capability) => {
    const content = `apiVersion: v1\nkind: Pod\nspec: {containers: [{securityContext: {capabilities: {add: [${capability}]}}}]}`;
    expect(k8sPrivilegedWorkloadMatcher.match(content, "pod.yaml")[0].matchedPattern).toBe(
      "dangerous Linux capability",
    );
    expect(
      k8sPrivilegedWorkloadMatcher.match(content.replace("add:", "drop:"), "pod.yaml"),
    ).toEqual([]);
  });

  it.each([
    "Pod",
    "Deployment",
    "PodList",
    "DeploymentList",
  ])("ignores custom API groups that reuse workload kind %s", (kind) => {
    const item = "{spec: {hostPID: true, template: {spec: {hostPID: true}}}}";
    const content = `apiVersion: example.com/v1\nkind: ${kind}\nspec: {hostPID: true, template: {spec: {hostPID: true}}}\nitems: [${item}]`;
    expect(k8sPrivilegedWorkloadMatcher.match(content, "custom.yaml")).toEqual([]);
  });

  it("scans first-party Kubernetes manifests under .github and ignores workflows", () => {
    const content = "apiVersion: v1\nkind: Pod\nspec: {hostPID: true}";
    expect(
      k8sPrivilegedWorkloadMatcher.match(content, ".github/kubernetes/pod.yaml")[0].matchedPattern,
    ).toBe("host namespace shared");
    expect(
      k8sPrivilegedWorkloadMatcher.match(
        "name: CI\non: [push]\njobs: {}",
        ".github/workflows/ci.yml",
      ),
    ).toEqual([]);
  });

  it("preserves unmatched block-scalar openings before a real multiline action", () => {
    const content = `apiVersion: v1
kind: Pod
metadata:
  annotations:
    note: |
      literal {{ fragment
  name: {{ printf "{{%s}}"
    .Values.name }}
spec: {hostPID: true}`;
    expect(k8sPrivilegedWorkloadMatcher.match(content, "pod.yaml")[0].lineNumbers).toEqual([9]);
  });

  it.each([
    ["apps/v1", "Deployment"],
    ["extensions/v1beta1", "DaemonSet"],
    ["batch/v1", "Job"],
    ["argoproj.io/v1alpha1", "Rollout"],
    ["apps.openshift.io/v1", "DeploymentConfig"],
  ])("scans %s %s and inherits the API version in its typed list", (apiVersion, kind) => {
    const content = `apiVersion: ${apiVersion}\nkind: ${kind}List\nitems:\n- spec: {template: {spec: {hostPID: true}}}`;
    expect(k8sPrivilegedWorkloadMatcher.match(content, "workload.yaml")[0].lineNumbers).toEqual([
      4,
    ]);
    expect(
      k8sPrivilegedWorkloadMatcher.match(
        content.replace(`${kind}List`, kind).replace("items:\n- spec:", "spec:"),
        "workload.yaml",
      )[0].matchedPattern,
    ).toBe("host namespace shared");
  });

  it.each([
    "apps/v1",
    "bogus",
    "v1/invalid",
  ])("does not treat %s Pods as core workloads", (apiVersion) => {
    const content = `apiVersion: ${apiVersion}\nkind: Pod\nspec: {hostPID: true}`;
    expect(k8sPrivilegedWorkloadMatcher.match(content, "pod.yaml")).toEqual([]);
  });
  it("follows deep merge chains without using the JavaScript call stack", () => {
    const content = [
      "defaults: &a0 {privileged: true}",
      ...Array.from({ length: 12_000 }, (_, i) => `x${i + 1}: &a${i + 1} {<<: *a${i}}`),
      "apiVersion: v1",
      "kind: Pod",
      "spec: {containers: [{securityContext: *a12000}]}",
    ].join("\n");
    expect(content.length).toBeLessThan(1024 * 1024);
    expect(k8sPrivilegedWorkloadMatcher.match(content, "pod.yaml")[0].lineNumbers).toEqual([1]);
  });

  it("uses explicit values and the first merge source even with cyclic merges", () => {
    const content = `safe: &safe {privileged: false}
dangerous: &dangerous {privileged: true}
cycle: &cycle {<<: [*cycle, *safe]}
apiVersion: v1
kind: Pod
spec:
  containers:
    - securityContext: {<<: [*safe, *dangerous]}
    - securityContext: {privileged: false, <<: *dangerous}
    - securityContext: {<<: *dangerous, privileged: null}
    - securityContext: {<<: *cycle}`;
    expect(k8sPrivilegedWorkloadMatcher.match(content, "pod.yaml")).toEqual([]);
  });

  it.each(["json", "yaml"])("reads escaped Kubernetes field names in %s", (extension) => {
    const content = '{"apiVersion": "v1", "k\\u0069nd": "Pod", "spec": {"hostPID": true}}';
    expect(k8sPrivilegedWorkloadMatcher.match(content, `pod.${extension}`)[0].matchedPattern).toBe(
      "host namespace shared",
    );
  });

  it("masks multiline Helm actions, quoted delimiters, and comments without moving lines", () => {
    const content = `{{- /*
This comment includes }} and a fake manifest:
apiVersion: v1
kind: Pod
spec: {hostPID: true}
*/ -}}
{{- if
  .Values.enabled
}}
apiVersion: v1
kind: Pod
metadata:
  name: {{ printf "}}%s"
    .Values.name }}
spec:
  containers:
    - securityContext: {privileged: true}
{{- end }}`;
    const [hit] = k8sPrivilegedWorkloadMatcher.match(content, "charts/app/templates/pod.yaml");
    expect(hit.matchedPattern).toBe("privileged container");
    expect(hit.lineNumbers).toEqual([17]);
    expect(hit.snippet).toContain("privileged: true");
  });

  it("masks adjacent standalone Helm actions and inline multiline comments", () => {
    const content = `{{ if .Values.enabled }}{{ end }}
apiVersion: v1
kind: Pod
metadata:
  name: app {{- /*
    comment with a closing delimiter }}
  */ -}}
spec: {hostPID: true}`;
    expect(k8sPrivilegedWorkloadMatcher.match(content, "pod.yaml")[0].lineNumbers).toEqual([8]);
  });

  it("bounds template-action processing", () => {
    const content = `${"{{}}".repeat(100_001)}\napiVersion: v1\nkind: Pod\nspec: {hostPID: true}`;
    expect(k8sPrivilegedWorkloadMatcher.match(content, "pod.yaml")).toEqual([]);
  });

  it("bounds lookup work in wide cyclic merge graphs without expanding aliases", () => {
    const content = [
      "cycle: &cycle {<<: *cycle}",
      `wide: &wide {<<: [${Array.from({ length: 140_000 }, () => "*cycle").join(",")}]}`,
      "apiVersion: v1",
      "kind: Pod",
      "spec: {securityContext: *wide, hostPID: true}",
    ].join("\n");
    expect(content.length).toBeLessThan(1024 * 1024);
    expect(k8sPrivilegedWorkloadMatcher.match(content, "pod.yaml")[0].matchedPattern).toBe(
      "host namespace shared",
    );
  });

  it.each([
    "SYS_BOOT",
    "SYS_TIME",
    "AUDIT_CONTROL",
    "IPC_OWNER",
  ])("detects host-impacting capability %s only when added", (capability) => {
    const prefix =
      "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - securityContext:\n        capabilities:";
    const added = `${prefix}\n          add: [${capability}]`;
    expect(k8sPrivilegedWorkloadMatcher.match(added, "pod.yaml")[0].matchedPattern).toBe(
      "dangerous Linux capability",
    );
    expect(k8sPrivilegedWorkloadMatcher.match(added.replace("add:", "drop:"), "pod.yaml")).toEqual(
      [],
    );
  });

  it("resolves aliases once and deduplicates their source locations", () => {
    const content = [
      "apiVersion: v1",
      "kind: Pod",
      "spec:",
      "  securityContext: &context {runAsUser: 0}",
      "  containers:",
      ...Array.from({ length: 1000 }, () => "    - securityContext: *context"),
    ].join("\n");
    expect(
      k8sPrivilegedWorkloadMatcher
        .match(content, "pod.yaml")
        .map((hit) => [hit.matchedPattern, hit.lineNumbers]),
    ).toEqual([["container runs as root UID", [4]]]);
  });

  it("uses the last mapping entry for duplicate Kubernetes fields", () => {
    const content =
      "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - securityContext: {privileged: true, privileged: false}";
    expect(k8sPrivilegedWorkloadMatcher.match(content, "pod.yaml")).toEqual([]);
  });
});

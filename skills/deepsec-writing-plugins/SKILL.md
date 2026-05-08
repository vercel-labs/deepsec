---
name: writing-deepsec-plugins
description: Author a deepsec plugin — the contract for matchers, notifiers, ownership providers, people directories, and remote executors. Activates when the user wants to package matchers for sharing or wire deepsec into Slack, GitHub Issues, CODEOWNERS, an internal directory, or remote infrastructure.
---

# Writing a deepsec plugin

A deepsec plugin can fill any of five slots:

| Slot | Purpose |
|---|---|
| `matchers` | Additional regex matchers, registered alongside the built-ins |
| `notifiers` | Where findings get reported (Slack, GitHub Issues, webhooks…) |
| `ownership` | Map files to owning teams/people (e.g. an internal directory) |
| `people` | Look up a person by email/name (managers, on-call, contact info) |
| `executor` | Run a deepsec command on remote infrastructure |

A single plugin can fill any subset.

## The contract

Source of truth: `packages/core/src/plugin.ts` (or
`.deepsec/node_modules/deepsec/dist/config.d.ts` for the published
types).

```ts
export interface DeepsecPlugin {
  name: string;
  matchers?: MatcherPlugin[];
  notifiers?: NotifierPlugin[];
  ownership?: OwnershipProvider;
  people?: PeopleProvider;
  executor?: ExecutorProvider;
  agents?: AgentPluginRef[];
  commands?: (program: unknown) => void;  // commander program
}
```

Plugins are loaded from `deepsec.config.ts`:

```ts
import { defineConfig } from "deepsec/config";
import myPlugin from "@my-org/deepsec-plugin";

export default defineConfig({
  projects: [{ id: "my-app", root: "../my-app" }],
  plugins: [myPlugin({ /* options */ })],
});
```

## Where to put your plugin

- **Org-internal**: a workspace package inside `.deepsec/`, or a sibling
  repo. pnpm/npm workspaces handle resolution.
- **Shared**: publish to npm under your scope.
- **Naming convention**: `@<scope>/plugin-<thing>` (Vite style), e.g.
  `@my-org/plugin-internal-services`.

## Slot 1: matchers (most common)

Same shape as a built-in matcher. See `writing-deepsec-matchers` for
how to author one.

```ts
// my-plugin/src/matchers/internal-rpc.ts
import type { MatcherPlugin, CandidateMatch } from "deepsec/config";
import { regexMatcher } from "deepsec/config";

export const internalRpcMatcher: MatcherPlugin = {
  slug: "internal-rpc-no-auth",
  description: "Internal RPC handler without auth interceptor",
  noiseTier: "precise",
  filePatterns: ["**/*.go"],
  match(content, filePath) {
    return regexMatcher("internal-rpc-no-auth", [
      { regex: /NewMyServiceHandler\s*\([^)]*\)/, label: "service handler" },
    ], content);
  },
};
```

```ts
// my-plugin/src/index.ts
import type { DeepsecPlugin } from "deepsec/config";
import { internalRpcMatcher } from "./matchers/internal-rpc.js";

export default function myPlugin(): DeepsecPlugin {
  return {
    name: "@my-org/plugin-internal-services",
    matchers: [internalRpcMatcher],
  };
}
```

```ts
// deepsec.config.ts
import myPlugin from "@my-org/plugin-internal-services";
export default defineConfig({
  projects: [/* … */],
  plugins: [myPlugin()],
});
```

Plugin matchers register alongside built-ins. **Slug collisions: the
plugin wins** (last-registered overrides) — useful for swapping a
built-in for a tighter org-specific version.

## Slot 2: ownership

Maps a file to the team or person that owns it. `deepsec enrich`
attaches this to findings — useful for routing notifications and
prioritizing review.

```ts
interface OwnershipProvider {
  name: string;
  fetchOwnership(args: {
    filePath: string;
    repo: string;
  }): Promise<OwnershipData | null>;
}
```

`OwnershipData` covers contributors, escalation teams, manager email,
on-call info. Source of truth: `packages/core/src/types.ts:OwnershipData`.

Return `null` when ownership data is unavailable; callers treat that
as a soft-fail.

A minimal ownership provider that reads from a `CODEOWNERS` file:

```ts
import type { OwnershipProvider } from "deepsec/config";
import fs from "node:fs";

export function codeownersProvider(rootPath: string): OwnershipProvider {
  return {
    name: "codeowners",
    async fetchOwnership({ filePath }) {
      // Parse CODEOWNERS, match filePath against globs, return
      // the first matching team/email. Return null on no match.
    },
  };
}
```

External plugins can wrap an internal directory or ownership oracle
the same way.

## Slot 3: people

Looks up a person by email or name and returns their metadata
(manager, slack handle, github username). Used by ownership and by
notifiers for @-mentions and escalation.

```ts
interface PeopleProvider {
  name: string;
  lookup(query: string): Promise<Person | null>;
  lookupManager?(person: Person): Promise<Person | null>;
}
```

`Person` has a generic core (`name`, `email`, `title`, `managerKey`)
plus an `extra` map for provider-specific fields (e.g. `slackId`,
`slackHandle`).

## Slot 4: notifiers

Where findings get reported. Slack, GitHub Issues, webhooks, an
internal incident system — whatever fits.

```ts
interface NotifierPlugin {
  name: string;
  notify(params: NotifyParams): Promise<FindingNotification>;
}
```

`NotifyParams` carries the finding, the FileRecord, and the
projectId. `FindingNotification` carries an `externalId` and
`externalUrl` for correlation back to the source.

deepsec doesn't ship a notifier in core. The original Slack notifier
was removed during open-sourcing because Slack belongs in a plugin. A
GitHub Issues notifier is a great first plugin to write.

## Slot 5: executor

Runs deepsec commands on remote infrastructure. The in-tree
`@vercel/sandbox` executor is the canonical example. Docker,
Kubernetes, and AWS-Batch executors all fit here.

```ts
interface ExecutorProvider {
  name: string;
  launch(req: ExecutorLaunchRequest, onLog: (m: string) => void): Promise<string>;  // runId
  collect(runId: string): Promise<void>;
  status?(runId: string): Promise<ExecutorStatus>;
}
```

The Vercel-Sandbox path lives in `packages/deepsec/src/sandbox/`; it's
not yet routed through `ExecutorProvider`. That refactor is on the
roadmap — for now, this is the most experimental slot of the five.

## Resolution order

Plugins are evaluated in the order of the `plugins: [...]` array.

- **`matchers`, `notifiers`, `agents`** — additive. All plugin
  contributions stack.
- **`ownership`, `people`, `executor`** — single-slot, last-wins. So a
  generic `codeowners` ownership plugin can load first and an
  org-specific oracle later in the array overrides it.

## Testing your plugin

Drop-in pattern:

```ts
// my-plugin/src/__tests__/plugin.test.ts
import { describe, expect, it } from "vitest";
import { createDefaultRegistry } from "deepsec/config";
import myPlugin from "../index.js";

describe("@my-org/plugin-internal-services", () => {
  it("contributes the expected matchers", () => {
    const plugin = myPlugin();
    const slugs = plugin.matchers!.map(m => m.slug);
    expect(slugs).toContain("internal-rpc-no-auth");
  });

  it("does not collide with built-ins", () => {
    const built = new Set(createDefaultRegistry().slugs());
    const plugin = myPlugin();
    for (const m of plugin.matchers ?? []) {
      // Either the slug is unique, or you're intentionally
      // overriding. Document overrides loudly.
    }
  });
});
```

## Hard rules

- **Document slug collisions loudly.** A plugin matcher silently
  overriding a built-in is a maintenance trap. If you intend to
  override, comment why; if not, rename the slug.
- **Return `null` on missing data, not a fake record.** Ownership /
  people consumers treat `null` as a soft-fail; a partial fake breaks
  notification routing.
- **Don't put org-specific code in core.** If a matcher names an
  internal helper or service, it belongs in a plugin, not upstreamed.

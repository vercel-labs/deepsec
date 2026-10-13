---
title: "Generated and hand-authored matchers"
description: "Review setup-generated declarative matchers and add richer project-specific matcher plugins when data-only patterns are not enough."
---

## Start with setup coverage

Normal initialization already asks whether custom matchers are needed:

```bash
npx deepsec init
```

The setup agent inventories repository ingress surfaces, runs the built-in
matchers, and applies a deterministic coverage policy. It generates matcher
proposals only for concrete gaps such as an uncovered internal RPC registry,
queue consumer family, or framework route primitive.

Accepted proposals are stored in `.deepsec/generated-matchers.ts` as strict
data and loaded through `generatedMatchersPlugin`. Review and commit this
file. Do not copy the generated setup inventory or setup-state file; those
are reproducible and gitignored.

## Declarative matcher safety contract

Generated specs are compiled by `compileDeclarativeMatchers`; model-written
TypeScript is never evaluated. Each spec declares:

- a unique kebab-case slug, description, and noise tier;
- constrained relative file globs;
- optional technology or sentinel-file gates;
- bounded regex sources using only `i`, `m`, or `im` flags;
- examples that every proposed matcher must actually match; and
- the inventory surface IDs the matcher claims to close.

Validation rejects unknown fields, traversal and catch-all globs, duplicate
slugs, empty-string regexes, backreferences, lookbehind, common exponential
backtracking shapes, huge repeats, and examples that do not fire.

After compilation, setup rescans and applies an explosion policy. A generated
matcher that reaches too many source files is removed from the plugin and its
persisted candidates are deleted before another attempt. Setup makes at most
two attempts per invocation and stops before processing if coverage still
fails. The stop is resumable: its actions point to the saved proposals and
coverage evidence, and re-running setup makes two fresh repair attempts.

## When to keep or edit a generated matcher

Keep it when its file scope and regex describe a stable repository primitive
and its candidate count is close to the corresponding entry-point count.

Edit or delete it when:

- the glob follows generated code rather than the real ingress family;
- the regex names an incidental identifier instead of the framework shape;
- examples do not represent real repository syntax;
- it claims a surface it does not actually reach; or
- a hand-authored matcher can express the condition more precisely.

After editing the data, run:

```bash
pnpm deepsec scan --matchers <slug>
pnpm deepsec setup
```

The first command is a focused spot-check; setup reconciles full coverage.

## When to write a hand-authored matcher

Declarative matchers are intentionally limited to safe regex sweeps. Write a
TypeScript `MatcherPlugin` when the rule needs:

- negative conditions, such as “route declaration without any auth helper”;
- multiple related searches over the same file;
- syntax-aware preprocessing or context windows;
- organization-specific semantics that should be reviewed as code; or
- a reusable public-framework/CWE rule worth contributing upstream.

Also consider a hand-authored matcher after a revalidated true positive shows
a stable sibling pattern that setup's entry-point coverage did not model.

## Hand-authored workspace layout

Keep richer matchers beside the generated plugin:

```text
.deepsec/
├── deepsec.config.ts
├── generated-matchers.ts
└── matchers/
    ├── my-route-no-auth.ts
    └── my-internal-rpc.ts
```

Register them through an additive inline plugin:

```ts
import { defineConfig, type DeepsecPlugin } from "deepsec/config";
import { generatedMatchersPlugin } from "./generated-matchers.js";
import { myRouteNoAuth } from "./matchers/my-route-no-auth.js";
import { myInternalRpc } from "./matchers/my-internal-rpc.js";

const projectMatchers: DeepsecPlugin = {
  name: "my-app-matchers",
  matchers: [myRouteNoAuth, myInternalRpc],
};

export default defineConfig({
  ai: { mode: "gateway", provider: "vercel" },
  projects: [{ id: "my-app", root: ".." }],
  plugins: [generatedMatchersPlugin, projectMatchers],
});
```

Slugs must be unique. The one-shot generator refuses built-in, plugin, and
intra-response collisions. Use a distinct slug for a hand-authored variant
rather than relying on replacement order.

## Matcher shape

```ts
import { regexMatcher, type MatcherPlugin } from "deepsec/config";

export const myInternalRpc: MatcherPlugin = {
  slug: "my-internal-rpc",
  description: "Internal RPC entry points",
  noiseTier: "normal",
  filePatterns: ["src/rpc/**/*.ts"],
  examples: ['registerRpc("users.get", handler)'],
  match(content) {
    return regexMatcher(
      "my-internal-rpc",
      [{ regex: /registerRpc\s*\(/g, label: "RPC registration" }],
      content,
    );
  },
};
```

Use the narrowest practical `filePatterns`. Avoid repository-wide noisy
globs. Inline `examples` are executable documentation: the scanner's matcher
example suite verifies that every example produces a candidate.

Noise tiers:

| Tier | Use when |
|---|---|
| `precise` | The matched syntax is itself a strong vulnerability signal. |
| `normal` | The pattern selects useful review candidates and the AI disambiguates. |
| `noisy` | Every file in a tightly bounded entry-point family deserves review. |

## Agent-assisted hand-authoring workflow

Ask a coding agent to read:

1. `.deepsec/data/<id>/setup/surface-inventory.json` for the intended surface;
2. `.deepsec/generated-matchers.ts` for already-covered gaps;
3. `.deepsec/data/<id>/files/` for candidate counts and revalidated findings;
4. `.deepsec/node_modules/deepsec/dist/config.d.ts` for `MatcherPlugin`; and
5. `.deepsec/node_modules/deepsec/dist/samples/webapp/` for richer examples.

Require it to explain the missed surface, propose a bounded matcher, add
examples, register the plugin without removing `generatedMatchersPlugin`, and
run a focused scan:

```bash
pnpm deepsec scan --matchers <new-slug>
```

Open several candidates, tune the matcher, then run the full scan/setup
reconciliation. Commit `deepsec.config.ts`, `generated-matchers.ts`, and
`matchers/`; do not commit generated `data/<id>/setup/` evidence.

## Contributing reusable matchers

If the shape belongs to a public framework or broadly applicable weakness,
add it to deepsec's built-in matcher registry instead of keeping an
organization-specific copy. Follow `CONTRIBUTING.md`, include representative
examples, and keep technology/sentinel gates as narrow as possible.

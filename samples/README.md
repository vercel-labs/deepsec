# Samples

Reference material for extending a workspace after one-shot setup. Start with
`npx deepsec init`; do not copy a sample as a replacement initializer.

## What's here

- [`webapp/`](webapp/) — a fictional Acme inventory webapp. Shows a
  hand-authored matcher plugin, an `INFO.md`, and per-project overrides. It
  complements setup-generated `generated-matchers.ts` by showing rules that
  need executable matcher logic.

Each sample is self-contained for repository tests. In a real workspace,
copy only the matcher/plugin ideas you need and keep the project link, `ai`
route, generated matcher plugin, and project registration created by setup.

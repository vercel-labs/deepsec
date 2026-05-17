# DeepSec Security Audit Report

Date: 2026-05-17
Target: `vercel-labs/deepsec`
Local workspace: `/Users/rk/code/deepsec-audit`
Audited baseline: `1475c4611ad8758a964ea57ef5ed053b2a8a6c59`
Working branch: `codex/deepsec-security-hardening`

## Executive Summary

This audit treated DeepSec as a security product that ingests untrusted repositories, executes repo-provided configuration/plugins, delegates analysis to local and sandboxed AI agents, persists model output, and can publish npm releases through GitHub OIDC. Those are high-risk trust boundaries.

The audit found and hardened multiple classes of issues:

- Secret exposure from PR/workflow execution and executable config.
- Credential brokering to attacker-controlled AI endpoints.
- Symlink/path traversal and unsafe data/state writes.
- Sandbox upload/download overreach.
- Model-output prompt injection and unsafe persistence/export/report rendering.
- Release OIDC job overprivilege.
- Dependency drift and a current `minimatch` advisory.

The largest residual architectural risk is local agent execution: local Codex/Claude modes still give model-directed tools broad read capability on the developer host. This cannot be fully solved with small patches without changing product behavior. The safest operational mode for untrusted code remains sandboxed execution plus no-secret config loading.

## Audit Method

The audit used parallel review streams plus local verification:

- 12 subagents reviewed independent slices: CLI/config/env, filesystem scanner, sandbox network/upload/download, agent prompt/output contracts, workflows/release, dependency supply chain, tests, dirty diff review, and threat model.
- Manual review covered code paths in `packages/core`, `packages/scanner`, `packages/processor`, `packages/deepsec`, `.github/workflows`, `e2e`, package metadata, and lockfile state.
- Baseline and final gates were run locally.
- No destructive git commands were used.

## Threat Model

Primary assets:

- AI provider credentials: `AI_GATEWAY_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `OPENAI_API_KEY`.
- Vercel Sandbox credentials: `VERCEL_TOKEN`, `VERCEL_TEAM_ID`, `VERCEL_PROJECT_ID`, OIDC tokens.
- npm Trusted Publishing OIDC capability.
- Developer/CI host files, shell environment, repo checkout, `.deepsec/data`.
- Integrity of findings, reports, exports, PR comments, and run metadata.

Primary trust boundaries:

- Untrusted target repo files and comments into agent prompts.
- Executable `deepsec.config.*` and plugin code.
- Sandbox VM result tarballs returning to the host.
- Local agent tools and shell sandboxes.
- GitHub workflow event context and secrets.
- npm package resolution in published and sandbox-installed modes.

## Findings And Fixes

### P0/P1 Fixed: Config And Env Secret Exposure

Risk:

The previous CLI path loaded dotenv and AI gateway defaults before config/plugin loading. Since `deepsec.config.ts` is executable repo code, a malicious config or plugin could read AI/Vercel/npm credentials or mutate process env before sandbox network policy was built.

Fixes:

- Removed top-level dotenv loading from `packages/deepsec/src/cli.ts`.
- Added scrubbed config/plugin registration: secret-like env keys are removed while `loadConfig()` and plugin command registration execute, then the original env is restored.
- `loadTrustedEnvFiles()` now runs only for commands that may instantiate agents: `process`, `revalidate`, `triage`, `sandbox`, `sandbox-all`.
- Added `packages/deepsec/src/env.ts` to load only operator-controlled env files.
- `.env` is deliberately ignored.
- Implicit `.env.local` is refused if tracked or symlinked.
- Explicit `DEEPSEC_ENV_FILE` remains an operator override.

Residual:

Config is still executable code. It can still run arbitrary local computation and read non-secret env during config loading. A future stronger design should add a safe JSON config mode or `--trust-config` gate for untrusted CI/direct scans.

### P0/P1 Fixed: Sandbox AI Credential Brokering To Attacker Hosts

Risk:

Sandbox network policy derived AI hosts from mutable environment. A config could set custom base URLs and `DEEPSEC_ALLOW_CUSTOM_AI_HOSTS=1`, causing brokered credentials to be injected toward an attacker-controlled host.

Fixes:

- `packages/deepsec/src/sandbox/setup.ts` now validates full AI endpoint URLs, not only hostnames.
- AI endpoints must be HTTPS.
- URLs with embedded credentials are rejected.
- Local/private hosts are rejected, including localhost, loopback, RFC1918, link-local, and common IPv6 local ranges.
- Non-standard ports are rejected unless custom hosts were allowed from the shell before config loading.
- `DEEPSEC_ALLOW_CUSTOM_AI_HOSTS` is snapshotted at module load from trusted shell env, so config/dotenv mutation cannot authorize custom hosts.
- Regression tests cover non-HTTPS, embedded credentials, localhost/private hosts, non-standard ports, and credential transforms.

Residual:

Explicit shell-level `DEEPSEC_ALLOW_CUSTOM_AI_HOSTS=1` still allows public custom HTTPS proxies. That is intentional but should be documented as a sensitive operator trust decision.

### P1 Fixed: Sandbox Upload Secret Overreach

Risk:

Git-mode sandbox upload previously used `git ls-files` and filtered only a small secret basename set. Tracked or untracked non-ignored secret-shaped files such as `kubeconfig`, gcloud ADC files, service-account files, `.netrc`, `.pypirc`, and nested env files could be uploaded.

Fixes:

- `packages/deepsec/src/sandbox/upload.ts` now applies exclude policy in git mode too.
- Secret basename denylist expanded.
- Symlinks are skipped in git and non-git tarball creation.
- Non-git tarball creation uses an explicit regular-file walk.
- Empty non-git tarballs are valid when all files are excluded.
- Bootstrap install now happens before target/data upload, with package lifecycle scripts ignored, reducing exposure of target code/data to dependency install scripts.

Residual:

Sandbox mode still uploads broad target/data context by design. The strongest future control would upload a manifest-scoped subset plus import closures, provide a dry-run upload manifest, and optionally run content-based secret scanning before upload.

### P1 Fixed: Sandbox Result Tarball Write Surface

Risk:

Sandbox result extraction allowed files, run metadata, and report artifacts in broad namespaces. The manifest check only constrained `files/`, leaving forged `runs/*.json` and `reports/report*` writable by a compromised sandbox worker.

Fixes:

- `packages/deepsec/src/sandbox/download.ts` now accepts command context.
- Worker result namespaces are restricted by command:
  - `process`/`revalidate`/`triage` cannot return report artifacts or run metadata.
  - `scan` may return run metadata.
  - `report` may return report artifacts.
- Extraction still validates regular files, allowed extensions, unsafe path segments, entry count, compressed/uncompressed size, and manifest file paths.
- Local download destination refuses symlinked data directories.

Residual:

Run/report schemas are not deeply validated on extraction beyond namespace/extension and later readers. Future work should validate run/report JSON shape before writing.

### P1 Fixed: Model Output Persistence And Report/Export Injection

Risk:

Agent-produced finding/revalidation/triage text could persist credentials or unsafe control sequences into `.deepsec/data`, reports, exports, and PR comments.

Fixes:

- `packages/core/src/run.ts` now sanitizes `FileRecord` before persistence.
- Candidate snippets for secret-bearing slugs are fully redacted.
- Credential-shaped values are redacted from candidates, findings, triage reasoning, revalidation reasoning, Codex stderr, refusal reason/raw/skipped text.
- Model-controlled text fields are capped to bounded lengths.
- Data writes now use atomic writes and refuse symlinked data directories below `DEEPSEC_DATA_ROOT`.
- `packages/deepsec/src/commands/report.ts` writes reports via safe data writes and strips ANSI/control/workflow-command shaped stdout text.
- `packages/deepsec/src/commands/export.ts` sanitizes issue titles, preserves `rawTitle` in metadata, escapes markdown text, and refuses symlink export directories/files.
- `md-dir` export cleanup is manifest-owned only; it no longer deletes arbitrary stale markdown from severity directories.

Residual:

Redaction is best-effort pattern matching, not a formal secret classifier. It materially reduces accidental leakage but cannot guarantee removal of every secret form.

### P1 Fixed: Revalidation Prompt Injection

Risk:

Revalidation prompts embedded model-produced findings as Markdown. A malicious earlier model output could inject instructions into a later revalidation pass.

Fixes:

- `packages/processor/src/agents/shared.ts` now serializes findings for revalidation as fenced JSON.
- The prompt explicitly labels that JSON as untrusted data, never instructions.
- Triple-backtick sequences are neutralized inside the JSON block.
- Revalidation output requires `findingIndex`, supports `LOW` adjusted severity, and validates verdict shape.

Residual:

This reduces second-order injection but does not prove the agent followed the instruction. Future provenance controls should tie verdicts to read evidence and line bounds.

### P1 Fixed: Agent Output Completeness And Run Status

Risk:

Malformed or incomplete agent output could be treated as empty findings or a successful run. Processing runs could complete as `done` despite failed batches/quota exhaustion.

Fixes:

- Investigation parser now fails loud on malformed JSON, unexpected paths, duplicate paths, omitted target files, invalid findings, and non-array finding lists.
- Parse errors report a SHA-256 prefix instead of echoing raw model output.
- `process()` now completes runs with phase `error` when any batch fails or quota is exhausted.
- Run stats include `errorBatchCount` and `quotaExhaustedSource`.
- Regression tests cover omitted verdicts, duplicate title disambiguation, quota stop behavior, and errored revalidation.

Residual:

Schema-valid findings are still not cryptographically or deterministically proven. Future work should require evidence snippets/line bounds from tool-read content and optionally dual-agent/deterministic revalidation before PR comments.

### P1 Fixed: Scanner Symlink And Skip Visibility

Risk:

Scanner and tech detection paths could miss directory sentinels or silently skip unreadable/unsafe/binary/oversized files. Broad test-directory ignores could hide deployed bypass endpoints.

Fixes:

- Added safe root-relative file/dir reads in `packages/scanner/src/safe-read.ts`.
- Scanner rejects absolute paths, backslashes, traversal, symlinks, binary files, and oversized files.
- Tech detection now distinguishes file and directory sentinels.
- Full scans now surface `skippedFiles` and record `filesSkipped` in run stats.
- Direct `scanFiles()` already refuses skipped listed files before agent processing.
- Removed broad `**/test/**`, `**/tests/**`, and `**/testserver/**` ignores while keeping explicit unit-test/fixture ignores.

Residual:

Skipping unreadable files is now visible, but full `scan` remains non-failing on skipped files. That is a product choice; strict mode could make skips fatal.

### P1 Fixed: Release Workflow OIDC Overprivilege

Risk:

The release job had `id-token: write` while installing dependencies, building, validating, and executing package lifecycle scripts. A dependency lifecycle compromise in the release job could request an OIDC token in the same trust boundary as npm publishing.

Fixes:

- `.github/workflows/release.yml` now splits release into:
  - `build-package`: no `id-token`, installs, validates, bundles, and creates `deepsec-*.tgz`.
  - `publish`: `id-token: write`, protected `npm-release` environment, downloads the tarball, verifies npm supports Trusted Publishing, and publishes the prebuilt tarball with `--ignore-scripts`.
- Removed mutable npm installation from the OIDC publish job.
- Workflow comments now require npm Trusted Publisher environment `npm-release`.

Residual:

The publish job still depends on runner-provided npm. It verifies minimum version and fails closed if unsupported.

### P1 Fixed: Workflow Secret Exposure

Risk:

DeepSec and live-sandbox workflows previously ran on PR-like contexts with secrets or long-lived credentials. The live sandbox test logged credential prefixes.

Fixes:

- `.github/workflows/e2e-live-sandbox.yml` is now `workflow_dispatch` only.
- DeepSec workflow changes already in the dirty tree made the AI-secret workflow manual/protected.
- Live sandbox test logs only set/unset status for credentials, no prefixes/hashes/lengths.

Residual:

Manual workflows still execute checked-out code with privileged credentials. Protected environments and reviewer gates should remain mandatory.

### P1 Fixed: Dependency Drift And Current Advisory

Risk:

Published `deepsec` dependencies used ranges and root `pnpm.overrides` did not protect downstream installs. `pnpm audit` also reported current `minimatch` and `brace-expansion` advisories.

Fixes:

- Published runtime dependencies in `packages/deepsec/package.json` are pinned to exact versions.
- Processor agent dependencies are pinned to exact versions.
- `minimatch` upgraded and pinned to `10.2.3` in `deepsec` and scanner.
- Lockfile regenerated.
- `pnpm audit --audit-level moderate` now reports no known vulnerabilities.

Residual:

Private workspace packages still rely on the monorepo lockfile for full reproducibility. Installed sandbox mode still cannot always use `--frozen-lockfile` because user `.deepsec` lockfile formats may vary.

## Verification

Final verification commands:

```text
pnpm -r build
pnpm test:unit
pnpm test:e2e
pnpm test:bundle
pnpm lint
pnpm knip
pnpm audit --audit-level moderate
```

Final results:

- Build: passed.
- Unit: passed, 2,138 tests.
- E2E: passed, 29 tests, 1 live-sandbox test skipped because it is credential-gated.
- Bundle E2E: passed, 24 tests.
- Lint: passed.
- Knip: passed.
- Audit: passed, no known vulnerabilities.

## Residual High-Value Work

1. Add a safe config mode.
   Executable config is still a trust boundary. Best future option: support declarative JSON config for CI/direct scans, and require `--trust-config` for executable plugins/matchers/commands.

2. Constrain local agents to repo-root read-only access.
   Local Codex/Claude modes can still be prompt-injected into reading host files outside the target repo. Strong fixes require a real filesystem sandbox or refusing local mode for untrusted repos.

3. Reduce sandbox upload scope.
   Upload only manifest files plus discovered import closure, provide a dry-run upload manifest, and run content-based secret screening before crossing the Vercel boundary.

4. Strengthen model-output provenance.
   Require line bounds to exist, require evidence from read files, detect suspicious all-empty outputs after high-risk scanner hits, and consider deterministic or dual-agent confirmation before PR comments.

5. Validate returned run/report JSON before extraction.
   Namespace restrictions reduce risk, but schema validation before write would be stronger.

6. Decide whether full-scan skipped files should be fatal.
   Current behavior surfaces counts and skipped paths. A `--strict-skips` mode would be appropriate for CI.

## Attack Tree After Fixes

Goal: compromise host secrets or DeepSec output integrity.

- Malicious repo config/plugin:
  - Cannot see scrubbed secret env during config load.
  - Can still execute arbitrary non-secret local code.
  - Future: safe config/trust gate.

- Prompt injection in target files:
  - Model output is bounded/redacted before persistence.
  - Revalidation receives prior findings as untrusted JSON.
  - Local agents can still read broad host files.
  - Future: repo-root FS sandbox/provenance checks.

- Sandbox worker compromise:
  - Real AI credentials stay host-side and are brokered by firewall transform.
  - AI egress host must be trusted HTTPS/public.
  - Returned tarballs are namespace/manifest/size/type constrained.
  - Future: schema validate run/report artifacts.

- CI/release compromise:
  - PR secret exposure reduced by manual workflows.
  - npm OIDC publish job no longer installs/builds/runs lifecycle scripts.
  - Future: policy tests for workflow secret/OIDC invariants.

## Bottom Line

The repo is substantially harder to exploit than the audited baseline. The most important fixes are in place and covered by tests. Remaining risk is architectural: DeepSec still analyzes untrusted code with powerful local AI tools and executable config/plugins. Treat local mode and executable config as trusted-code paths; use sandboxed/manual/protected workflows for untrusted repositories.

import { type NetworkPolicy, type NetworkPolicyRule, Sandbox } from "@vercel/sandbox";
import { markSetupComplete } from "./download.js";
import { trackSandbox, untrackSandbox } from "./shutdown.js";
import { extractTarballOnSandbox, type TarballStats, uploadTarballToSandbox } from "./upload.js";

const DEEPSEC_DIR = "/vercel/sandbox/deepsec-app";
const DATA_DIR = "/vercel/sandbox/deepsec-app/data";
const TARGET_DIR = "/vercel/sandbox/target";

export { DATA_DIR, DEEPSEC_DIR, TARGET_DIR };

/**
 * Whether the running CLI lives inside the source repo (`dev`) or inside a
 * user's `.deepsec/node_modules/deepsec` install (`installed`). Drives:
 *   - which directory gets tarballed and uploaded
 *   - whether `pnpm install --frozen-lockfile` is safe (only in dev, where
 *     we ship our own lockfile; the user's `.deepsec/` may carry a lockfile
 *     written by a different pnpm major than the one we install in-sandbox)
 *   - which CLI entrypoint workers invoke (tsx source vs. installed bin)
 */
export type DeepsecMode = "dev" | "installed";

const ONE_DAY_MS = 24 * 60 * 60 * 1000;
const SNAPSHOT_EXPIRATION_MS = 1 * ONE_DAY_MS;

// --- Tarball bundle passed from the orchestrator ---

export interface UploadBundle {
  /** tar.gz of the local deepsec app (source only, no node_modules/.git/data) */
  app: TarballStats;
  /** tar.gz of the local target working copy (no .git) */
  target: TarballStats;
  /** tar.gz of the local data/<projectId>/ directory */
  data: TarballStats;
}

// --- Sandbox env vars ---

// Routing / debug knobs the agent reads inside the sandbox. AI credential
// env vars (ANTHROPIC_AUTH_TOKEN, OPENAI_API_KEY, AI_GATEWAY_API_KEY) are
// deliberately absent — they're brokered via firewall header injection
// (see resolveBrokeredCredentials + buildWorkerNetworkPolicy below) so a
// compromised in-VM agent can't read them out of /proc/<pid>/environ.
const SANDBOX_ENV_KEYS: string[] = ["ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "DEEPSEC_AGENT_DEBUG"];

/**
 * The Anthropic / OpenAI SDKs throw at construction if no auth token is set.
 * We need *something* in env so the SDK builds, but the value must not be a
 * real secret — the firewall transform below replaces it on every outbound
 * request. Deliberately recognizable so a curious greppy reader knows it's
 * a decoy. Length is set to keep the agent SDK's "looks like a token" sniff
 * tests happy without resembling any real provider format.
 */
const BROKERED_TOKEN_PLACEHOLDER = "deepsec-sandbox-brokered-credential";

/**
 * Real credentials live on the orchestrator host only. The sandbox sees a
 * placeholder; the firewall replaces the Authorization header at egress
 * with the real token.
 */
interface BrokeredCredentials {
  anthropicToken?: string;
  openaiToken?: string;
}

/**
 * Resolve the orchestrator-side AI credentials that will be brokered into
 * the sandbox. AI Gateway issues one token per team that authenticates both
 * Claude and OpenAI traffic, so when only ANTHROPIC_AUTH_TOKEN is set and
 * the worker is going to run codex, fall it back as the OpenAI token.
 */
export function resolveBrokeredCredentials(agentType: string | undefined): BrokeredCredentials {
  const anthropicToken = process.env.ANTHROPIC_AUTH_TOKEN;
  const explicitOpenai = process.env.OPENAI_API_KEY;
  // Only borrow ANTHROPIC for OPENAI on the codex path — and only when the
  // user hasn't pinned an explicit OpenAI key. Outside codex this fallback
  // would never hit the network anyway, but scoping it keeps intent clear.
  const openaiToken = explicitOpenai ?? (agentType === "codex" ? anthropicToken : undefined);
  return { anthropicToken, openaiToken };
}

const PROXY_PORT = 8787;
const PROXY_URL = `http://127.0.0.1:${PROXY_PORT}`;
// Path differs by upload mode (see DeepsecMode):
//   dev       — uploaded source workspace, proxy lives at its source location
//   installed — user's `.deepsec/` workspace; after `pnpm install` the deepsec
//               package is materialized under node_modules/deepsec/, with the
//               proxy script bundled into dist/ by build.mjs.
const PROXY_SCRIPT_BY_MODE: Record<DeepsecMode, string> = {
  dev: `${DEEPSEC_DIR}/packages/deepsec/src/sandbox/request-proxy.mjs`,
  installed: `${DEEPSEC_DIR}/node_modules/deepsec/dist/sandbox/request-proxy.mjs`,
};
const CODEX_HOME = "/vercel/sandbox/.codex";

export function buildSandboxEnv(
  agentType: string | undefined,
  credentials: BrokeredCredentials,
): Record<string, string> {
  const env: Record<string, string> = {};
  for (const key of SANDBOX_ENV_KEYS) {
    if (key in process.env) env[key] = process.env[key]!;
  }

  // Decoy tokens. Real values stay on the orchestrator host; the firewall
  // transform overwrites Authorization at egress. We only emit a placeholder
  // when the orchestrator actually has a real token to broker — otherwise
  // we let the SDK fail loudly at init rather than 401 later from upstream.
  if (credentials.anthropicToken) {
    env["ANTHROPIC_AUTH_TOKEN"] = BROKERED_TOKEN_PLACEHOLDER;
  }
  if (credentials.openaiToken) {
    env["OPENAI_API_KEY"] = BROKERED_TOKEN_PLACEHOLDER;
  }

  // Belt-and-suspenders alongside the worker egress firewall: the master
  // kill-switch covers DISABLE_TELEMETRY / DISABLE_ERROR_REPORTING /
  // DISABLE_AUTOUPDATER / DISABLE_FEEDBACK_COMMAND. The Codex CLI doesn't
  // honour env vars for its analytics — its config.toml is written into
  // CODEX_HOME by createBootstrapSnapshot and baked into the snapshot.
  env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1";

  // Claude SDK traffic goes through a local proxy that strips
  // `eager_input_streaming` from tool schemas (Bedrock rejects it).
  //
  // Codex traffic goes straight to the gateway — there's no Bedrock-style
  // body mutation needed for Codex, so a proxy hop would just add latency
  // and a base-url-rewriting hazard (path doubling, etc.). spawnFromSnapshot
  // skips the proxy startup when agentType=codex for the same reason.
  if (agentType === "codex") {
    env["CODEX_HOME"] = CODEX_HOME;
    if (!env["OPENAI_BASE_URL"] && env["ANTHROPIC_BASE_URL"]) {
      env["OPENAI_BASE_URL"] = env["ANTHROPIC_BASE_URL"];
    }
  } else {
    const realBaseUrl = env["ANTHROPIC_BASE_URL"];
    if (realBaseUrl) {
      env["ANTHROPIC_UPSTREAM_BASE_URL"] = realBaseUrl;
      env["ANTHROPIC_BASE_URL"] = PROXY_URL;
    }
  }
  return env;
}

// --- Worker egress firewall + credential brokering ---
//
// Workers should only reach the AI host the SDK/proxy actually forwards to.
// We derive that from the upstream base URL already present in the env, and
// fall back to the documented hosts when env parsing fails so we never end
// up applying an effective deny-all by accident.
//
// On top of allowlisting, we use the SDK's per-domain `transform.headers`
// feature to inject the Authorization header at the firewall layer. The
// real bearer token never enters the VM — code inside the sandbox sees
// only the BROKERED_TOKEN_PLACEHOLDER. The firewall's egress proxy MITMs
// TLS using a Vercel-installed CA trusted by the sandbox image, so it can
// rewrite headers on encrypted requests.

// One default per backend — Claude agents never make OpenAI-host calls and
// vice versa, so allowing both was over-permissive. Specifically, with
// brokering on, allowing the off-backend host means the firewall would have
// no rule to inject credentials there, but a curious agent could still try
// to reach it; better to deny outright.
const DEFAULT_ANTHROPIC_HOST = "api.anthropic.com";
const DEFAULT_OPENAI_HOST = "api.openai.com";

function hostFromUrl(u: string | undefined): string | null {
  if (!u) return null;
  try {
    return new URL(u).hostname;
  } catch {
    return null;
  }
}

export function buildWorkerNetworkPolicy(
  env: Record<string, string>,
  agentType: string | undefined,
  credentials: BrokeredCredentials = {},
  extraAllow: string[] = [],
): NetworkPolicy {
  const isCodex = agentType === "codex";

  // Single AI host per backend. Prefer derived from the base URL the agent
  // will actually use; fall back to the provider's documented default when
  // the user hasn't configured one.
  const aiHost = isCodex
    ? (hostFromUrl(env["OPENAI_BASE_URL"]) ?? DEFAULT_OPENAI_HOST)
    : (hostFromUrl(env["ANTHROPIC_UPSTREAM_BASE_URL"]) ?? DEFAULT_ANTHROPIC_HOST);

  // The fallback flips at resolveBrokeredCredentials — by here, openaiToken
  // already carries the ANTHROPIC gateway token if the user only set that
  // one and is running codex.
  const injectToken = isCodex ? credentials.openaiToken : credentials.anthropicToken;

  const allow: Record<string, NetworkPolicyRule[]> = {
    [aiHost]: injectToken
      ? [
          {
            transform: [{ headers: { authorization: `Bearer ${injectToken}` } }],
          },
        ]
      : [],
  };
  for (const h of extraAllow) {
    if (!(h in allow)) allow[h] = [];
  }
  return { allow };
}

// --- Bootstrap: one sandbox does full setup, snapshots, stops ---

interface BootstrapOptions {
  projectId: string;
  /** Which agent backend the workers will run — drives which native binary we install */
  agentType?: string;
  vcpus: number;
  timeout: number;
  /** Source repo vs. user's `.deepsec/` install — see DeepsecMode docstring */
  mode: DeepsecMode;
  bundle: UploadBundle;
  onLog: (msg: string) => void;
}

function getNonOidcCreds() {
  if (process.env.VERCEL_TEAM_ID && process.env.VERCEL_PROJECT_ID && process.env.VERCEL_TOKEN) {
    return {
      teamId: process.env.VERCEL_TEAM_ID,
      projectId: process.env.VERCEL_PROJECT_ID,
      token: process.env.VERCEL_TOKEN,
    };
  }
}

/**
 * Stand up a fresh sandbox, upload everything, install deps, ensure native
 * binaries, then snapshot and stop. Returns the snapshot id — workers use it
 * as their seed. The sandbox is always stopped before return (success or fail)
 * to avoid leaking compute.
 */
export async function createBootstrapSnapshot(opts: BootstrapOptions): Promise<string> {
  const agentType = opts.agentType ?? "claude-agent-sdk";
  // Bootstrap doesn't make AI calls — it just installs deps and snapshots.
  // We pass empty credentials so no placeholder tokens are written into the
  // snapshot env; workers spawned from the snapshot get fresh placeholders
  // tied to whatever the orchestrator's credentials are at spawn time.
  const sandboxEnv = buildSandboxEnv(agentType, {});

  opts.onLog("Creating bootstrap sandbox...");
  let sandbox: Sandbox;
  try {
    sandbox = await Sandbox.create({
      runtime: "node24",
      env: sandboxEnv,
      resources: { vcpus: opts.vcpus },
      timeout: opts.timeout,
      ...getNonOidcCreds(),
    });
  } catch (err: any) {
    throw new Error(`Sandbox.create failed: ${err?.message ?? String(err)}`);
  }

  opts.onLog(`Bootstrap sandbox ${sandbox.sandboxId} created.`);
  trackSandbox(sandbox);

  try {
    // Install pnpm globally
    await runAndLog(sandbox, "npm", ["install", "-g", "pnpm@8"], "/vercel/sandbox", opts.onLog, {
      sudo: true,
    });
    opts.onLog("  pnpm installed.");

    // Install ripgrep + python3 — Codex agents prefer rg/python over grep/awk
    // for whole-tree searches, and several investigation patterns lean on
    // python3 for parsing AST / JSON. Best-effort: warn but don't fail the
    // whole bootstrap if the package manager rejects either one.
    await installAgentTools(sandbox, opts.onLog);

    // Upload app + target + data in parallel
    const appTar = "/tmp/deepsec-app.tar.gz";
    const targetTar = "/tmp/deepsec-target.tar.gz";
    const dataTar = "/tmp/deepsec-data.tar.gz";
    const projectDataDir = `${DATA_DIR}/${opts.projectId}`;

    // Each uploadTarballToSandbox call frees the local temp tarball as soon
    // as the upload completes, so peak host-side memory is bounded by the
    // largest single tarball (not the sum of all three).
    await Promise.all([
      (async () => {
        await uploadTarballToSandbox(sandbox, appTar, opts.bundle.app.tarPath, opts.onLog);
        await extractTarballOnSandbox(sandbox, appTar, DEEPSEC_DIR, opts.onLog);
      })(),
      (async () => {
        await uploadTarballToSandbox(sandbox, targetTar, opts.bundle.target.tarPath, opts.onLog);
        await extractTarballOnSandbox(sandbox, targetTar, TARGET_DIR, opts.onLog);
      })(),
      (async () => {
        await uploadTarballToSandbox(sandbox, dataTar, opts.bundle.data.tarPath, opts.onLog);
        await extractTarballOnSandbox(sandbox, dataTar, projectDataDir, opts.onLog);
      })(),
    ]);

    // Install dependencies. --frozen-lockfile only in dev mode: our source
    // workspace ships a lockfile written by the same pnpm major (8) we
    // install in the sandbox above. The user's `.deepsec/` install in
    // installed mode may have been generated by a newer pnpm whose lockfile
    // format pnpm@8 rejects (ERR_PNPM_LOCKFILE_BREAKING_CHANGE), so we
    // resolve fresh there.
    const installArgs = opts.mode === "dev" ? ["install", "--frozen-lockfile"] : ["install"];
    opts.onLog(`Running pnpm ${installArgs.join(" ")}...`);
    await runAndLog(sandbox, "pnpm", installArgs, DEEPSEC_DIR, opts.onLog);

    // Ensure agent native binaries. Both backends ship vendored native binaries
    // through optional deps; pnpm's optional-dep filter on the host platform
    // doesn't always land the right binary on the sandbox. We install the
    // matching binary explicitly per agent.
    if (agentType === "codex") {
      opts.onLog("Ensuring Codex CLI native binary is installed...");
      await ensureCodexNativeBinary(sandbox, opts.onLog);
      await writeCodexConfig(sandbox, opts.onLog);
    } else {
      opts.onLog("Ensuring Claude SDK native binaries are installed...");
      await ensureClaudeNativeBinaries(sandbox, opts.onLog);
    }

    // Snapshot the prepared state
    opts.onLog("Snapshotting bootstrap sandbox...");
    const snap = await sandbox.snapshot({ expiration: SNAPSHOT_EXPIRATION_MS });
    opts.onLog(`Bootstrap snapshot: ${snap.snapshotId}`);

    return snap.snapshotId;
  } finally {
    try {
      await sandbox.stop();
    } catch {}
    untrackSandbox(sandbox);
    opts.onLog(`Bootstrap sandbox ${sandbox.sandboxId} stopped.`);
  }
}

// --- Worker: spawn from snapshot, no upload ---

interface SpawnOptions {
  snapshotId: string;
  /** Drives which API base URL gets rewritten to the local proxy */
  agentType?: string;
  vcpus: number;
  timeout: number;
  /** Source repo vs. user's `.deepsec/` install — see DeepsecMode docstring */
  mode: DeepsecMode;
  /** Extra hostnames to allow through the worker's egress firewall, on top of the AI host derived from base URLs */
  allowedHosts?: string[];
  onLog: (msg: string) => void;
}

/**
 * Create a worker sandbox from the bootstrap snapshot. Re-touches the
 * setup-done marker so the post-run delta detection (`find -newer`) captures
 * only files modified during the worker's run. Also starts the local
 * request-proxy that mediates outbound API traffic for the active agent.
 */
export async function spawnFromSnapshot(opts: SpawnOptions): Promise<Sandbox> {
  // Resolve once. The same `credentials` object is the source of truth for
  // (a) what placeholders to expose in the sandbox env (so the SDK builds)
  // and (b) which Authorization header the firewall transform should inject.
  // Reading process.env directly here keeps the real token out of any data
  // structure that's later passed to Sandbox.create({ env }).
  const credentials = resolveBrokeredCredentials(opts.agentType);
  const sandboxEnv = buildSandboxEnv(opts.agentType, credentials);
  const networkPolicy = buildWorkerNetworkPolicy(
    sandboxEnv,
    opts.agentType,
    credentials,
    opts.allowedHosts,
  );

  let sandbox: Sandbox;
  try {
    sandbox = await Sandbox.create({
      source: { type: "snapshot", snapshotId: opts.snapshotId },
      env: sandboxEnv,
      resources: { vcpus: opts.vcpus },
      timeout: opts.timeout,
      networkPolicy,
      ...getNonOidcCreds(),
    });
  } catch (err: any) {
    const details = [err?.message];
    if (err?.response?.status) details.push(`status: ${err.response.status}`);
    if (err?.body) details.push(`body: ${JSON.stringify(err.body).slice(0, 300)}`);
    throw new Error(`Sandbox.create from snapshot failed: ${details.filter(Boolean).join(" | ")}`);
  }

  trackSandbox(sandbox);

  // Reset the setup marker so worker-local file modifications are detected
  // via `find -newer`. The marker time baked into the snapshot would work in
  // theory, but resetting is cheap and more robust against clock skew.
  await markSetupComplete(sandbox);

  // The local request-proxy exists to strip `eager_input_streaming` from
  // Anthropic-bound tool schemas (Bedrock rejects it). Only the
  // claude-agent-sdk backend needs it. Codex talks directly to the
  // gateway without body mutation; custom plugin agents own their own
  // transport. Allowlisting by name (rather than "everyone except codex")
  // keeps a stub agent out of the proxy startup, which fails fast when
  // ANTHROPIC_UPSTREAM_BASE_URL isn't set — letting the live-sandbox e2e
  // run with no AI credentials.
  if (opts.agentType === "claude-agent-sdk") {
    await startRequestProxy(sandbox, opts.mode, opts.onLog);
  }

  return sandbox;
}

async function startRequestProxy(
  sandbox: Sandbox,
  mode: DeepsecMode,
  onLog: (msg: string) => void,
): Promise<void> {
  const proxyScript = PROXY_SCRIPT_BY_MODE[mode];
  // Background-launch the proxy. Using nohup + setsid + redirecting stdio so
  // the process survives the runCommand's lifecycle.
  await sandbox.runCommand({
    cmd: "sh",
    args: ["-c", `nohup node ${proxyScript} > /tmp/request-proxy.log 2>&1 &`],
  });

  // Wait until the port accepts connections (up to ~5s). If it never comes
  // up, the Claude SDK will fail with ECONNREFUSED and our retry will fire.
  const script = `
for i in $(seq 1 50); do
  if (echo > /dev/tcp/127.0.0.1/${PROXY_PORT}) 2>/dev/null; then
    echo "proxy ready after \${i} attempts"
    exit 0
  fi
  sleep 0.1
done
echo "proxy did not come up in 5s"
cat /tmp/request-proxy.log 2>/dev/null | tail -20
exit 1
`;
  const check = await sandbox.runCommand({
    cmd: "bash",
    args: ["-c", script],
  });
  const out = (await check.stdout()) + (await check.stderr());
  for (const line of out.split("\n")) {
    if (line.trim()) onLog(`  ${line}`);
  }
  if (check.exitCode !== 0) {
    throw new Error(`request-proxy failed to start (exit ${check.exitCode})`);
  }
}

// --- Native binary remediation (shared helper) ---

async function ensureClaudeNativeBinaries(
  sandbox: Sandbox,
  onLog: (msg: string) => void,
): Promise<void> {
  const script = `
set -e
cd ${DEEPSEC_DIR}
SDK_VER=""
for CANDIDATE in \\
  ./node_modules/@anthropic-ai/claude-agent-sdk \\
  ./packages/processor/node_modules/@anthropic-ai/claude-agent-sdk \\
  ./node_modules/.pnpm/@anthropic-ai+claude-agent-sdk@*/node_modules/@anthropic-ai/claude-agent-sdk; do
  for DIR in $CANDIDATE; do
    if [ -f "$DIR/package.json" ]; then
      SDK_VER=$(node -p "require('$DIR/package.json').version" 2>/dev/null)
      break 2
    fi
  done
done
if [ -z "$SDK_VER" ]; then
  echo "Could not detect Claude SDK version"
  exit 1
fi
echo "Detected Claude SDK version: $SDK_VER"

# SDK picks -musl path first; if sandbox is glibc but musl binary lives there,
# exec fails with ENOENT (loader missing). Detect libc and install the
# matching libc's binary into BOTH the musl and non-musl SDK paths.
LIBC=gnu
if ldd /bin/ls 2>&1 | grep -qi musl; then LIBC=musl; fi
echo "  Sandbox libc: $LIBC"

SRC_SUFFIX=""
[ "$LIBC" = "musl" ] && SRC_SUFFIX="-musl"

for ARCH in x64 arm64; do
  SRC_VARIANT="linux-\${ARCH}\${SRC_SUFFIX}"
  SRC_PKG="@anthropic-ai/claude-agent-sdk-\${SRC_VARIANT}"
  echo "  Fetching \${SRC_PKG}@\${SDK_VER}..."
  rm -rf /tmp/claude-native-fetch && mkdir -p /tmp/claude-native-fetch
  cd /tmp/claude-native-fetch
  npm pack "\${SRC_PKG}@\${SDK_VER}" --silent 2>&1 | tail -1
  tar -xzf ./*.tgz
  if [ ! -f package/claude ]; then
    echo "  ERROR: \${SRC_PKG}@\${SDK_VER} does not contain claude binary"
    exit 1
  fi
  SIZE=$(stat -c%s package/claude 2>/dev/null || stat -f%z package/claude 2>/dev/null || echo "?")
  for DEST_VARIANT in "linux-\${ARCH}-musl" "linux-\${ARCH}"; do
    PNPM_KEY="@anthropic-ai+claude-agent-sdk-\${DEST_VARIANT}@\${SDK_VER}"
    DEST_PKG="@anthropic-ai/claude-agent-sdk-\${DEST_VARIANT}"
    TARGET_DIR="${DEEPSEC_DIR}/node_modules/.pnpm/\${PNPM_KEY}/node_modules/\${DEST_PKG}"
    mkdir -p "\${TARGET_DIR}"
    cp package/claude "\${TARGET_DIR}/claude"
    chmod +x "\${TARGET_DIR}/claude"
    echo "    → \${DEST_VARIANT}/claude (\${SIZE} bytes, from \${SRC_VARIANT})"
  done
done
rm -rf /tmp/claude-native-fetch
`;

  const result = await sandbox.runCommand({
    cmd: "bash",
    args: ["-c", script],
  });
  const stdout = await result.stdout();
  const stderr = await result.stderr();
  for (const line of (stdout + stderr).split("\n")) {
    if (line.trim()) onLog(`  ${line}`);
  }
  if (result.exitCode !== 0) {
    throw new Error(`Claude native binary install failed (exit ${result.exitCode})`);
  }
}

/**
 * Install ripgrep + python3 in the bootstrap sandbox so the Codex agent has
 * efficient whole-tree search and a scripting language for ad-hoc analysis.
 * Detects the available package manager (dnf / microdnf / yum / apt-get).
 *
 * Best-effort: if neither tool can be installed, we log and move on. The
 * agent can fall back to grep / awk / shell.
 */
async function installAgentTools(sandbox: Sandbox, onLog: (msg: string) => void): Promise<void> {
  const script = `
set -u
log() { echo "  $*"; }

PM=""
for candidate in dnf microdnf yum apt-get apk; do
  if command -v "$candidate" >/dev/null 2>&1; then PM="$candidate"; break; fi
done
if [ -z "$PM" ]; then
  log "No supported package manager (dnf/microdnf/yum/apt-get/apk) — skipping rg/python3 install"
  exit 0
fi
log "Detected package manager: $PM"

install_with() {
  local pkg="$1"
  case "$PM" in
    dnf|microdnf|yum)
      $PM install -y "$pkg" 2>&1 | tail -5
      ;;
    apt-get)
      apt-get update -qq 2>&1 | tail -2
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$pkg" 2>&1 | tail -5
      ;;
    apk)
      apk add --no-cache "$pkg" 2>&1 | tail -5
      ;;
  esac
}

# ripgrep: try the package manager first (Debian/Ubuntu/Alpine ship it),
# then fall back to the official static musl binary on GitHub releases —
# Amazon Linux 2023 / RHEL / older yum-based distros don't have ripgrep
# in their default repos.
install_rg_from_github() {
  local arch=""
  case "$(uname -m)" in
    x86_64) arch="x86_64-unknown-linux-musl" ;;
    aarch64|arm64) arch="aarch64-unknown-linux-gnu" ;;
    *) log "WARN: unsupported arch $(uname -m) for ripgrep prebuilt"; return 1 ;;
  esac
  local rel="14.1.1"
  local url="https://github.com/BurntSushi/ripgrep/releases/download/\${rel}/ripgrep-\${rel}-\${arch}.tar.gz"
  log "Downloading ripgrep \${rel} (\${arch}) from GitHub..."
  rm -rf /tmp/rg-fetch && mkdir -p /tmp/rg-fetch && cd /tmp/rg-fetch
  if ! curl -fsSL --retry 3 -o rg.tar.gz "\${url}"; then
    log "WARN: ripgrep download failed: \${url}"
    return 1
  fi
  tar -xzf rg.tar.gz
  local bin
  bin=$(find . -maxdepth 3 -name rg -type f | head -1)
  if [ -z "\${bin}" ]; then
    log "WARN: rg binary not found in tarball"
    return 1
  fi
  install -m 0755 "\${bin}" /usr/local/bin/rg
  cd / && rm -rf /tmp/rg-fetch
}

if command -v rg >/dev/null 2>&1; then
  log "rg already installed: $(rg --version | head -1)"
else
  log "Installing ripgrep via package manager..."
  install_with ripgrep || true
  if ! command -v rg >/dev/null 2>&1; then
    install_rg_from_github || true
  fi
  if command -v rg >/dev/null 2>&1; then
    log "rg ready: $(rg --version | head -1)"
  else
    log "WARN: rg still not on PATH — agent will fall back to grep"
  fi
fi

# python3: usually preinstalled on AL2023 / Ubuntu, but cover the edge case
if command -v python3 >/dev/null 2>&1; then
  log "python3 already installed: $(python3 --version)"
else
  log "Installing python3..."
  install_with python3 || log "WARN: python3 install failed"
  command -v python3 >/dev/null 2>&1 && log "python3 ready: $(python3 --version)" || log "WARN: python3 still not on PATH"
fi
exit 0
`;
  const result = await sandbox.runCommand({
    cmd: "bash",
    args: ["-c", script],
    sudo: true,
  });
  const stdout = await result.stdout();
  const stderr = await result.stderr();
  for (const line of (stdout + stderr).split("\n")) {
    if (line.trim()) onLog(line);
  }
  // Don't throw on non-zero — best-effort.
}

/**
 * Codex CLI ships a vendored Rust binary via platform-specific optional
 * dependencies (e.g. `@openai/codex-linux-x64`). pnpm running on the bootstrap
 * host (Mac arm64 typically) installs only host-matching optional deps, so the
 * sandbox often comes up without the linux binary it needs.
 *
 * We resolve the SDK version, force-install the linux variant matching the
 * sandbox arch via `npm pack`, and place its `vendor/<triple>/codex/` tree
 * where the bin script (`bin/codex.js`) looks it up via `require.resolve`.
 *
 * Codex linux binaries are statically linked musl, so they run on glibc
 * sandboxes too — no libc detection needed.
 */
async function ensureCodexNativeBinary(
  sandbox: Sandbox,
  onLog: (msg: string) => void,
): Promise<void> {
  const script = `
set -e
cd ${DEEPSEC_DIR}
SDK_VER=""
for CANDIDATE in \\
  ./node_modules/@openai/codex \\
  ./packages/processor/node_modules/@openai/codex \\
  ./node_modules/.pnpm/@openai+codex-sdk@*/node_modules/@openai/codex \\
  ./node_modules/.pnpm/@openai+codex@*/node_modules/@openai/codex; do
  for DIR in $CANDIDATE; do
    if [ -f "$DIR/package.json" ]; then
      SDK_VER=$(node -p "require('$DIR/package.json').version" 2>/dev/null)
      break 2
    fi
  done
done
if [ -z "$SDK_VER" ]; then
  echo "Could not detect Codex CLI version"
  exit 1
fi
echo "Detected Codex CLI version: $SDK_VER"

# Map sandbox arch to platform package + vendor triple
UNAME_M=$(uname -m)
case "$UNAME_M" in
  x86_64) ARCH=x64; TRIPLE=x86_64-unknown-linux-musl ;;
  aarch64|arm64) ARCH=arm64; TRIPLE=aarch64-unknown-linux-musl ;;
  *) echo "Unsupported arch: $UNAME_M"; exit 1 ;;
esac
echo "  Sandbox arch: $UNAME_M (linux-\${ARCH}, $TRIPLE)"

# The platform package's actual published version is "<sdk_ver>-linux-<arch>".
PLATFORM_PKG="@openai/codex-linux-\${ARCH}"
PLATFORM_VER="\${SDK_VER}-linux-\${ARCH}"

echo "  Fetching @openai/codex@\${PLATFORM_VER} (platform binary)..."
rm -rf /tmp/codex-native-fetch && mkdir -p /tmp/codex-native-fetch
cd /tmp/codex-native-fetch
npm pack "@openai/codex@\${PLATFORM_VER}" --silent 2>&1 | tail -1
tar -xzf ./*.tgz
if [ ! -f "package/vendor/\${TRIPLE}/codex/codex" ]; then
  echo "  ERROR: vendor/\${TRIPLE}/codex/codex not present in tarball"
  ls -la package/vendor/ 2>/dev/null || true
  exit 1
fi
SIZE=$(stat -c%s "package/vendor/\${TRIPLE}/codex/codex" 2>/dev/null || echo "?")

# pnpm stores platform packages under the alias name — drop the binary at every
# place pnpm might have created (or expects) the vendor tree.
PNPM_KEY="@openai+codex-linux-\${ARCH}@\${PLATFORM_VER}"
DEST_PATHS=(
  "${DEEPSEC_DIR}/node_modules/.pnpm/\${PNPM_KEY}/node_modules/\${PLATFORM_PKG}"
  "${DEEPSEC_DIR}/node_modules/\${PLATFORM_PKG}"
)
for DEST in "\${DEST_PATHS[@]}"; do
  mkdir -p "\${DEST}/vendor/\${TRIPLE}/codex"
  cp "package/vendor/\${TRIPLE}/codex/codex" "\${DEST}/vendor/\${TRIPLE}/codex/codex"
  chmod +x "\${DEST}/vendor/\${TRIPLE}/codex/codex"
  cp package/package.json "\${DEST}/package.json"
  echo "    → \${DEST} (\${SIZE} bytes)"
done
rm -rf /tmp/codex-native-fetch
`;

  const result = await sandbox.runCommand({
    cmd: "bash",
    args: ["-c", script],
  });
  const stdout = await result.stdout();
  const stderr = await result.stderr();
  for (const line of (stdout + stderr).split("\n")) {
    if (line.trim()) onLog(`  ${line}`);
  }
  if (result.exitCode !== 0) {
    throw new Error(`Codex native binary install failed (exit ${result.exitCode})`);
  }
}

/**
 * Codex doesn't honour env vars for telemetry — its controls live in
 * config.toml under CODEX_HOME. We bake the file into the bootstrap
 * snapshot so every worker inherits it. Belt-and-suspenders to the egress
 * firewall, which would already block the analytics endpoints; this just
 * keeps the SDK from logging connection-refused noise.
 */
async function writeCodexConfig(sandbox: Sandbox, onLog: (msg: string) => void): Promise<void> {
  const configToml = `# Written by deepsec sandbox bootstrap. Disables non-AI egress
# (analytics, update checks, OTEL exporters) so the agent stays within
# the sandbox firewall allowlist.
check_for_update_on_startup = false

[analytics]
enabled = false

[otel]
metrics_exporter = "none"
trace_exporter = "none"
`;
  const mkdir = await sandbox.runCommand({
    cmd: "mkdir",
    args: ["-p", CODEX_HOME],
  });
  if (mkdir.exitCode !== 0) {
    throw new Error(`Failed to create ${CODEX_HOME} (exit ${mkdir.exitCode})`);
  }
  await sandbox.writeFiles([
    { path: `${CODEX_HOME}/config.toml`, content: Buffer.from(configToml) },
  ]);
  onLog(`  Codex config.toml written to ${CODEX_HOME}/config.toml (telemetry/updates disabled).`);
}

async function runAndLog(
  sandbox: Sandbox,
  cmd: string,
  args: string[],
  cwd: string,
  _onLog: (msg: string) => void,
  extraOpts?: { sudo?: boolean },
): Promise<void> {
  const result = await sandbox.runCommand({
    cmd,
    args,
    cwd,
    sudo: extraOpts?.sudo,
  });
  if (result.exitCode !== 0) {
    const stderr = (await result.stderr()).trim();
    const stdout = (await result.stdout()).trim();
    // Include BOTH streams. pnpm in particular writes errors to stdout while
    // emitting unrelated warnings (DEP0169 from `url.parse()`) on stderr —
    // showing only stderr hides the real failure.
    const sections: string[] = [];
    if (stdout) sections.push(`--- stdout ---\n${stdout}`);
    if (stderr) sections.push(`--- stderr ---\n${stderr}`);
    const body = sections.length > 0 ? `\n${sections.join("\n")}` : "";
    throw new Error(
      `Command failed: ${cmd} ${args.join(" ")} (exit ${result.exitCode}, cwd ${cwd})${body}`,
    );
  }
}

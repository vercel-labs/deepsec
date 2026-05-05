import { chmodSync, cpSync, mkdirSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const __dirname = dirname(fileURLToPath(import.meta.url));
const distDir = resolve(__dirname, "dist");
const repoRoot = resolve(__dirname, "../..");

// Externalized at runtime: native binaries, heavy SDKs, and jiti (which
// bundles its own esbuild — re-bundling it produces broken output).
const external = [
  "@anthropic-ai/claude-agent-sdk",
  "@openai/codex",
  "@openai/codex-sdk",
  "@vercel/sandbox",
  "jiti",
  "tar",
];

const common = {
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
  external,
  sourcemap: false,
  legalComments: "none",
  logLevel: "info",
};

rmSync(distDir, { recursive: true, force: true });
mkdirSync(distDir, { recursive: true });

// CJS deps bundled into ESM use `require()` for Node builtins; give them a
// real `require` via createRequire so the call resolves at runtime.
const requireShim = `
import { createRequire as __topLevelCreateRequire } from "node:module";
const require = __topLevelCreateRequire(import.meta.url);
`.trim();

await build({
  ...common,
  entryPoints: [resolve(__dirname, "src/cli.ts")],
  outfile: resolve(distDir, "cli.mjs"),
  banner: { js: `#!/usr/bin/env node\n${requireShim}` },
});
chmodSync(resolve(distDir, "cli.mjs"), 0o755);

await build({
  ...common,
  entryPoints: [resolve(__dirname, "src/config.ts")],
  outfile: resolve(distDir, "config.mjs"),
  banner: { js: requireShim },
});

cpSync(resolve(repoRoot, "docs"), resolve(distDir, "docs"), { recursive: true });
cpSync(resolve(repoRoot, "samples"), resolve(distDir, "samples"), {
  recursive: true,
  filter: (src) => !/(^|\/)data(\/|$)/.test(src) && !/(^|\/)node_modules(\/|$)/.test(src),
});

// The request-proxy is a standalone .mjs that runs on the sandbox worker
// (not bundled into cli.mjs — it executes in its own node process). Ship it
// verbatim so installed-mode workers can spawn it from node_modules/deepsec/.
mkdirSync(resolve(distDir, "sandbox"), { recursive: true });
cpSync(
  resolve(__dirname, "src/sandbox/request-proxy.mjs"),
  resolve(distDir, "sandbox/request-proxy.mjs"),
);

// README.md, LICENSE, and NOTICE live at the workspace root for repo
// browsing. `files` in package.json names them at the package root, so
// stage them here.
cpSync(resolve(repoRoot, "README.md"), resolve(__dirname, "README.md"));
cpSync(resolve(repoRoot, "LICENSE"), resolve(__dirname, "LICENSE"));
cpSync(resolve(repoRoot, "NOTICE"), resolve(__dirname, "NOTICE"));

console.log("\nBundle complete:");
console.log("  dist/cli.mjs");
console.log("  dist/config.mjs");
console.log("  dist/sandbox/request-proxy.mjs");
console.log("  dist/docs/");
console.log("  dist/samples/");
console.log("  README.md");
console.log("  LICENSE");
console.log("  NOTICE");

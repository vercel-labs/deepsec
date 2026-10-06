import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "e2e",
    globalSetup: ["./global-setup.ts"],
    include: ["**/*.test.ts"],
    testTimeout: 30_000,
    // The live-sandbox test spawns the bundled CLI for ~5+ minutes
    // with `stdio: inherit` so the operator can watch sandbox bootstrap
    // progress. With the default `forks` pool, that subprocess output
    // goes worker→pipe→main, sharing the same channel as vitest's
    // worker-to-main RPC. The RPC has a hardcoded 60s timeout (in
    // `birpc`); on a long, log-heavy run, periodic `onTaskUpdate`
    // calls back up behind the inherited stdio and time out, surfacing
    // as a noisy `[vitest-worker]: Timeout calling "onTaskUpdate"`
    // unhandled error AFTER the test passes.
    //
    // `threads` uses Node `worker_threads`, which share file
    // descriptors with the main process — child stdout/stderr inherit
    // straight to the user's terminal without going through vitest's
    // RPC pipe, so RPC stays unsaturated.
    pool: "threads",
  },
});

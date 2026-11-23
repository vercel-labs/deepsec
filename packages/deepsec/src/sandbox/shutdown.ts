import type { Sandbox } from "@vercel/sandbox";

/**
 * Tracks sandboxes created by the orchestrator so we can stop them when the
 * parent CLI receives SIGINT/SIGTERM. Best-effort — stop calls are fired in
 * parallel and we exit whether they succeed or not.
 */

const live = new Set<Sandbox>();
const cleanups = new Set<() => void>();
let installed = false;
let shuttingDown = false;

/**
 * Run `fn` (synchronously) if the CLI is interrupted, before exiting.
 * Returns a function that unregisters it.
 */
export function addShutdownCleanup(fn: () => void): () => void {
  installHandlers();
  cleanups.add(fn);
  return () => {
    cleanups.delete(fn);
  };
}

export function trackSandbox(sandbox: Sandbox): void {
  installHandlers();
  live.add(sandbox);
}

export function untrackSandbox(sandbox: Sandbox): void {
  live.delete(sandbox);
}

function installHandlers(): void {
  if (installed) return;
  installed = true;

  const handler = (signal: NodeJS.Signals) => {
    if (shuttingDown) {
      // Second ctrl+c — hard-exit
      process.stderr.write("\n(force-exit)\n");
      process.exit(130);
    }
    shuttingDown = true;
    for (const fn of cleanups) {
      try {
        fn();
      } catch {}
    }
    cleanups.clear();
    const count = live.size;
    process.stderr.write(
      `\nReceived ${signal}. Stopping ${count} sandbox${count === 1 ? "" : "es"}...\n`,
    );

    // Fire all .stop()s in parallel; give them up to 10s total before exiting.
    const sandboxes = Array.from(live);
    live.clear();
    const stops = sandboxes.map((s) =>
      s
        .stop()
        .then(() => {
          process.stderr.write(`  stopped ${s.sandboxId}\n`);
        })
        .catch((err) => {
          process.stderr.write(`  stop failed ${s.sandboxId}: ${err?.message ?? err}\n`);
        }),
    );

    Promise.race([Promise.all(stops), new Promise((r) => setTimeout(r, 10_000))]).finally(() => {
      process.exit(signal === "SIGINT" ? 130 : 143);
    });
  };

  process.on("SIGINT", handler);
  process.on("SIGTERM", handler);
}

// Caps stdout/stderr of the deepsec worker when it runs inside a sandbox.
//
// Everything the worker writes flows back to the orchestrator through the
// sandbox NDJSON log stream, which is parsed with unbounded JSON.parse in
// @vercel/sandbox. The orchestrator caps what it *consumes*
// (see sandbox/orchestrator.ts), but a single oversized record can still
// OOM the SDK before that cap applies — so the worker must never emit one.
// Long lines are truncated at the source and, once the total budget is
// spent, all further output is dropped.
//
// The orchestrator only pattern-matches batch-complete lines as a sync
// nudge; its download poller has a 15s timer fallback, so suppressed
// output degrades politeness, not correctness.

const MAX_LINE_CHARS = 2_000;
const MAX_TOTAL_BYTES = 8 * 1024 * 1024;

type CapState = { remainingBytes: number; exhausted: boolean };

type MinimalWritable = {
  write(chunk: unknown, encoding?: unknown, callback?: unknown): boolean;
};

function truncateLines(text: string): string {
  if (text.length <= MAX_LINE_CHARS) return text;
  return text
    .split("\n")
    .map((line) =>
      line.length > MAX_LINE_CHARS ? `${line.slice(0, MAX_LINE_CHARS)}… [line truncated]` : line,
    )
    .join("\n");
}

/** Exported for tests. Patches `stream.write` against a shared budget. */
export function capStream(stream: MinimalWritable, state: CapState): void {
  const orig = stream.write.bind(stream);
  stream.write = (chunk: unknown, encoding?: unknown, callback?: unknown): boolean => {
    if (typeof encoding === "function") {
      callback = encoding;
      encoding = undefined;
    }
    if (state.exhausted) {
      if (typeof callback === "function") (callback as () => void)();
      return true;
    }
    const text = truncateLines(
      typeof chunk === "string"
        ? chunk
        : Buffer.isBuffer(chunk)
          ? chunk.toString("utf8")
          : String(chunk),
    );
    state.remainingBytes -= Buffer.byteLength(text);
    if (state.remainingBytes <= 0) {
      state.exhausted = true;
      return orig(
        `${text}\n[deepsec: sandbox output cap reached; further logs suppressed]\n`,
        callback,
      );
    }
    return orig(text, encoding, callback);
  };
}

/**
 * No-op outside a sandbox (DEEPSEC_INSIDE_SANDBOX !== "1"). Inside one,
 * caps process.stdout and process.stderr against a shared byte budget.
 */
export function installSandboxOutputCap(): void {
  if (process.env.DEEPSEC_INSIDE_SANDBOX !== "1") return;
  const state: CapState = { remainingBytes: MAX_TOTAL_BYTES, exhausted: false };
  capStream(process.stdout, state);
  capStream(process.stderr, state);
}

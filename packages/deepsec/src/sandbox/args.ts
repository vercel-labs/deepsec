/**
 * Shared passthrough-argument helpers for `sandbox` and `sandbox-all`.
 *
 * Both commands forward unknown options to the deepsec subcommand that runs
 * inside the worker, but a few of them also drive host-side decisions
 * (credential brokering, partitioning, route selection). Reading both
 * `--flag value` and `--flag=value` here keeps those decisions in sync with
 * what the worker will actually parse.
 */

/** Value of `--flag value` or `--flag=value`; undefined when absent or valueless. */
export function extractFlag(args: string[], flag: string): string | undefined {
  const idx = args.indexOf(flag);
  if (idx !== -1) {
    const value = args[idx + 1];
    if (value !== undefined && !value.startsWith("--")) return value;
    return undefined;
  }
  const prefix = `${flag}=`;
  for (const arg of args) {
    if (!arg.startsWith(prefix)) continue;
    const value = arg.slice(prefix.length);
    return value.length > 0 ? value : undefined;
  }
  return undefined;
}

export function hasFlag(args: string[], flag: string): boolean {
  return args.includes(flag);
}

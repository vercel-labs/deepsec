export function shouldUseHeadlessMode(
  options: { headless?: boolean; nonInteractive?: boolean },
  streams: { stdinIsTTY?: boolean; stdoutIsTTY?: boolean } = {
    stdinIsTTY: process.stdin.isTTY,
    stdoutIsTTY: process.stdout.isTTY,
  },
): boolean {
  return (
    options.headless === true ||
    options.nonInteractive === true ||
    streams.stdinIsTTY !== true ||
    streams.stdoutIsTTY !== true
  );
}

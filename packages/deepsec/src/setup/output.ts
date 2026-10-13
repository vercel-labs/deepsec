import { StringDecoder } from "node:string_decoder";

// Covers CSI color/cursor sequences and OSC title/hyperlink sequences. Child
// output is persisted as text, never replayed as terminal control.
const ANSI_SEQUENCE = /\u001B(?:\][^\u0007]*(?:\u0007|\u001B\\)|\[[0-?]*[ -/]*[@-~])/g;

export function normalizeTerminalLine(value: string, maxChars = 2_000): string {
  const normalized = value
    .replace(ANSI_SEQUENCE, "")
    .replaceAll("\u0008", "")
    .replaceAll("\u0000", "")
    .trimEnd();
  return normalized.length > maxChars
    ? `${normalized.slice(0, maxChars)}… [truncated]`
    : normalized;
}

/** Decode arbitrary byte chunks into CR/LF-delimited, terminal-safe lines. */
export function createTerminalLineDecoder(onLine: (line: string) => void): {
  write(chunk: Buffer): void;
  end(): void;
} {
  const decoder = new StringDecoder("utf8");
  let pending = "";
  const consume = (value: string, flush: boolean) => {
    pending += value;
    const parts = pending.split(/\r\n|[\r\n]/);
    const tail = parts.pop() ?? "";
    pending = flush ? "" : tail;
    for (const part of parts) {
      const line = normalizeTerminalLine(part);
      if (line.trim()) onLine(line);
    }
    if (flush && tail.trim()) onLine(normalizeTerminalLine(tail));
  };
  return {
    write(chunk) {
      consume(decoder.write(chunk), false);
    },
    end() {
      consume(decoder.end(), true);
    },
  };
}

export function packageInstallProgress(
  line: string,
  expectedPackages?: number,
): { current?: number; total?: number; expectedPackages?: number } | undefined {
  const packageCount = line.match(/^Packages:\s+\+(\d+)/)?.[1];
  if (packageCount) return { expectedPackages: Number(packageCount) };
  const added = line.match(/^Progress:.*\badded\s+(\d+)/)?.[1];
  if (!added) return undefined;
  return {
    current: Number(added),
    total: expectedPackages,
    expectedPackages,
  };
}

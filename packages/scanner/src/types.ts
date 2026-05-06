import type { FileRecord, MatcherPlugin } from "@deepsec/core";

// Re-export for backwards compat with consumers that import from @deepsec/scanner.
export type { MatcherPlugin, NoiseTier } from "@deepsec/core";

export interface ScanProgress {
  type: "file_scanned" | "matcher_started" | "matcher_done";
  message: string;
  filePath?: string;
  matcherSlug?: string;
  matchCount?: number;
  /**
   * Index of the current matcher in the run order (1-based) and the
   * total active matchers. Set on `matcher_started` and `matcher_done`
   * for the matcher phase only — the glob phase already conveys its own
   * progress via the message string. The CLI uses these to render a
   * progress bar without knowing the registry up-front.
   */
  matcherIndex?: number;
  matcherTotal?: number;
}

export interface ScannerDriver {
  scan(params: {
    root: string;
    matchers: MatcherPlugin[];
    projectId: string;
    runId: string;
    /** Extra ignore globs merged with the driver's built-in defaults */
    ignorePaths?: string[];
  }): AsyncGenerator<ScanProgress, FileRecord[]>;
}

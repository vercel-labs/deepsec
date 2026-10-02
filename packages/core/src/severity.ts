import type { Severity } from "./types.js";

/**
 * Canonical severity ranking used for filtering and presentation.
 * Lower numbers are more severe.
 */
export const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  HIGH_BUG: 3,
  BUG: 4,
  LOW: 5,
};

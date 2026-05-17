export const SANDBOX_LIMITS = {
  maxSandboxes: 50,
  maxVcpus: 8,
  maxConcurrency: 64,
  maxBatchSize: 50,
  maxLimit: 100_000,
  minTimeoutMs: 60_000,
  maxTimeoutMs: 12 * 60 * 60 * 1000,
} as const;

export function boundedInt(
  value: number | undefined,
  label: string,
  defaults: { defaultValue: number; min: number; max: number },
): number {
  const n = value ?? defaults.defaultValue;
  if (!Number.isInteger(n) || n < defaults.min || n > defaults.max) {
    throw new Error(`${label} must be an integer between ${defaults.min} and ${defaults.max}`);
  }
  return n;
}

function boundedOptionalInt(
  value: number | undefined,
  label: string,
  bounds: { min: number; max: number },
): number | undefined {
  if (value === undefined || value === 0) return undefined;
  if (!Number.isInteger(value) || value < bounds.min || value > bounds.max) {
    throw new Error(`${label} must be an integer between ${bounds.min} and ${bounds.max}`);
  }
  return value;
}

export function parseBoundedFlag(
  raw: string | undefined,
  label: string,
  defaults: { defaultValue: number; min: number; max: number },
): number {
  if (raw === undefined) return defaults.defaultValue;
  const n = Number(raw);
  return boundedInt(n, label, defaults);
}

export function parseBoundedOptionalFlag(
  raw: string | undefined,
  label: string,
  bounds: { min: number; max: number },
): number | undefined {
  if (raw === undefined) return undefined;
  const n = Number(raw);
  return boundedOptionalInt(n, label, bounds);
}

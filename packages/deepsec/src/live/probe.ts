import { createHash } from "node:crypto";
import http from "node:http";
import https from "node:https";
import {
  type BlockerKind,
  evidenceHeaderAllowlist,
  type HttpMethod,
  type LiveEvidence,
  type LiveLimits,
  type LiveScopeManifest,
  type ProbeObservation,
  REDACTED,
  redactSecretValues,
  sensitiveRequestHeaders,
} from "@deepsec/core";

// ---------------------------------------------------------------------------
// HTTP probe executor (Milestone 1, loopback only).
//
// The privileged half of the typed plan -> policy check -> probe -> typed
// assertion -> evidence invariant. Everything a probe does is gated on the
// approved scope manifest; everything it observes is sanitized before it can
// reach an artifact. See "Probe tool contract" in plans/live-investigations.md.
// ---------------------------------------------------------------------------

/** Rejection thrown before any request is sent (a policy decision, not a target error). */
export class PolicyViolation extends Error {
  readonly kind: BlockerKind;

  constructor(kind: BlockerKind, message: string) {
    super(message);
    this.name = "PolicyViolation";
    this.kind = kind;
  }
}

/** Thrown when a unit exceeds its per-unit request budget. */
export class BudgetExceeded extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BudgetExceeded";
  }
}

/** A target-side failure after the request was sent (timeout, connection error, ...). */
export class ProbeNetworkError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProbeNetworkError";
  }
}

export interface ProbeRequest {
  unitRef: string;
  method: HttpMethod;
  /** Path + optional query string, resolved against the scope's base URL. */
  path: string;
  headers?: Record<string, string>;
  purpose: string;
}

export interface ProbeRunnerOptions {
  scope: LiveScopeManifest;
  /**
   * Exact secret values to redact wherever they appear in recorded metadata.
   * Values only — never persisted, never returned.
   */
  secrets?: readonly string[];
  now?: () => number;
}

/** sha256 hex helper for body hashes. */
function sha256Hex(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex");
}

/** True for http(s) URLs whose hostname is a loopback address or `localhost`. */
export function isLoopbackUrl(rawUrl: string): boolean {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return false;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return false;
  const host = url.hostname.toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  if (host === "::1" || host === "[::1]") return true;
  // IPv4 loopback is the whole 127.0.0.0/8 block.
  return /^127(?:\.\d{1,3}){3}$/.test(host);
}

/**
 * The default ports a scheme implies; explicit ports must match exactly.
 */
function defaultPort(protocol: string): string {
  return protocol === "https:" ? "443" : "80";
}

function portOf(url: URL): string {
  return url.port || defaultPort(url.protocol);
}

/**
 * True when `candidate` and `allowed` are the same origin (scheme, host, and
 * port — an explicit default port equals an omitted one).
 */
export function originEquals(candidate: URL, allowed: URL): boolean {
  return (
    candidate.protocol === allowed.protocol &&
    candidate.hostname.toLowerCase() === allowed.hostname.toLowerCase() &&
    portOf(candidate) === portOf(allowed)
  );
}

/** True when `url`'s path starts with any of the scope's allowed path prefixes. */
function pathAllowed(pathname: string, prefixes: readonly string[]): boolean {
  return prefixes.some((p) => pathname.startsWith(p));
}

/**
 * Exact-origin egress check: `url` must share scheme+host+port with the
 * scope's base URL or one of its allowedOrigins. http→https downgrade of an
 * allowlisted https origin is a scheme mismatch and rejected here; every
 * non-allowlisted origin is rejected here. Loopback targets are allowed when
 * the scope approves them (the sample-app loop); non-loopback plain-http
 * origins are rejected unless explicitly allowlisted.
 */
export function originAllowed(url: URL, scope: LiveScopeManifest): boolean {
  if (url.protocol !== "http:" && url.protocol !== "https:") return false;
  const candidates = [scope.baseUrl, ...scope.allowedOrigins];
  for (const raw of candidates) {
    let allowed: URL;
    try {
      allowed = new URL(raw);
    } catch {
      continue;
    }
    if (originEquals(url, allowed)) return true;
  }
  return false;
}

/**
 * A probe runner bound to one approved scope. Enforces origin/method/path
 * policy, per-unit budgets, a rate cap, response-byte caps, and timeouts;
 * never follows redirects; and sanitizes every observation (allowlisted
 * headers, redacted credentials, no bodies — byte counts and hashes only).
 */
export class ProbeRunner {
  private readonly scope: LiveScopeManifest;
  private readonly limits: LiveLimits;
  private readonly secrets: readonly string[];
  private readonly now: () => number;
  private readonly baseUrl: URL;
  private readonly headerAllowlist = evidenceHeaderAllowlist();
  private readonly sensitiveHeaders = sensitiveRequestHeaders();
  private requestTimestamps: number[] = [];
  private requestCounter = 0;

  constructor(opts: ProbeRunnerOptions) {
    this.scope = opts.scope;
    this.limits = opts.scope.limits;
    this.secrets = opts.secrets ?? [];
    this.now = opts.now ?? Date.now;
    this.baseUrl = new URL(opts.scope.baseUrl);
  }

  /** True when the scope's target is loopback (approval is a no-op there). */
  get isLoopback(): boolean {
    return isLoopbackUrl(this.scope.baseUrl);
  }

  /**
   * Validate a request against policy without sending it. Throws
   * PolicyViolation / BudgetExceeded on rejection.
   */
  check(req: ProbeRequest, requestsSoFarInUnit: number): URL {
    if (requestsSoFarInUnit >= this.limits.maxRequestsPerUnit) {
      throw new BudgetExceeded(
        `Unit ${req.unitRef} exhausted its request budget (${this.limits.maxRequestsPerUnit})`,
      );
    }
    if (!this.scope.allowedMethods.includes(req.method)) {
      throw new PolicyViolation(
        "scope-expansion",
        `Method ${req.method} is not in the approved scope (${this.scope.allowedMethods.join(", ")})`,
      );
    }
    let url: URL;
    try {
      url = new URL(req.path, this.baseUrl);
    } catch {
      throw new PolicyViolation("scope-expansion", `Unparseable path: ${JSON.stringify(req.path)}`);
    }
    if (url.username !== "" || url.password !== "") {
      throw new PolicyViolation("scope-expansion", "Credentials embedded in the request URL");
    }
    if (!originAllowed(url, this.scope)) {
      throw new PolicyViolation(
        "scope-expansion",
        `Origin ${url.origin} is outside the approved scope (${this.baseUrl.origin})`,
      );
    }
    if (!pathAllowed(url.pathname, this.scope.allowedPathPrefixes)) {
      throw new PolicyViolation(
        "scope-expansion",
        `Path ${url.pathname} is outside the approved prefixes (${this.scope.allowedPathPrefixes.join(", ")})`,
      );
    }
    this.enforceRateLimit();
    return url;
  }

  /**
   * Execute one policy-approved request. Redirects are never followed; a
   * redirect response is recorded (Location as data) and returned.
   */
  async request(req: ProbeRequest, requestsSoFarInUnit: number): Promise<ProbeObservation> {
    const url = this.check(req, requestsSoFarInUnit);
    const startedAt = this.now();
    const requestId = `${req.unitRef}#${++this.requestCounter}`;

    const result = await this.send(url, req);
    const timingMs = Math.max(0, this.now() - startedAt);

    // Sanitize response headers: allowlist names, redact secret values. The
    // body never leaves this function — only its byte count and hash.
    const headers: Record<string, string> = {};
    for (const [name, value] of Object.entries(result.headers)) {
      const lower = name.toLowerCase();
      if (!this.headerAllowlist.has(lower)) continue;
      const joined = Array.isArray(value) ? value.join("; ") : (value ?? "");
      headers[lower] = redactSecretValues(joined, this.secrets);
    }

    const observation: ProbeObservation = {
      requestId,
      request: this.recordRequest(req, url),
      status: result.status,
      headers,
      bodyBytes: result.bodyBytes,
      bodyTruncated: result.bodyTruncated,
      bodyHash: result.bodyHash,
      timingMs,
    };

    const location = result.headers.location;
    if (typeof location === "string" && location.length > 0) {
      let locationOrigin: string | undefined;
      let locationInScope = false;
      try {
        const loc = new URL(location, url);
        locationOrigin = loc.origin;
        locationInScope = originAllowed(loc, this.scope);
      } catch {
        locationOrigin = undefined;
      }
      observation.redirect = {
        location: redactSecretValues(location, this.secrets),
        locationOrigin,
        locationInScope,
      };
    }

    return observation;
  }

  /** Token-bucket-free rate cap: at most maxRequestsPerMinute in the trailing 60s. */
  private enforceRateLimit(): void {
    const now = this.now();
    const windowStart = now - 60_000;
    this.requestTimestamps = this.requestTimestamps.filter((t) => t > windowStart);
    if (this.requestTimestamps.length >= this.limits.maxRequestsPerMinute) {
      throw new BudgetExceeded(
        `Rate limit reached: ${this.limits.maxRequestsPerMinute} request(s) per minute`,
      );
    }
    this.requestTimestamps.push(now);
  }

  /** Sanitized record of the request as sent (no credential values). */
  private recordRequest(req: ProbeRequest, url: URL) {
    const query: Record<string, string> = {};
    for (const [key, value] of url.searchParams) {
      query[key] = redactSecretValues(value, this.secrets);
    }
    const headerNames: string[] = [];
    const headerValues: Record<string, string> = {};
    for (const [name, value] of Object.entries(req.headers ?? {})) {
      const lower = name.toLowerCase();
      if (!this.headerAllowlist.has(lower) && !this.sensitiveHeaders.has(lower)) continue;
      headerNames.push(lower);
      headerValues[lower] = this.sensitiveHeaders.has(lower)
        ? REDACTED
        : redactSecretValues(value, this.secrets);
    }
    return {
      method: req.method,
      path: url.pathname,
      query,
      headerNames: headerNames.sort(),
      headerValues,
      purpose: req.purpose,
    };
  }

  private send(
    url: URL,
    req: ProbeRequest,
  ): Promise<{
    status: number;
    headers: http.IncomingHttpHeaders;
    bodyBytes: number;
    bodyTruncated: boolean;
    bodyHash: string;
  }> {
    return new Promise((resolve, reject) => {
      const transport = url.protocol === "https:" ? https : http;
      const request = transport.request(
        url,
        {
          method: req.method,
          headers: {
            "user-agent": "deepsec-live-probe/0.1 (+https://github.com/vercel-labs/seczero)",
            "x-deepsec-unit": req.unitRef,
            ...(req.headers ?? {}),
          },
          // Never follow redirects automatically: Node's http(s).request does
          // not follow them at all, so a 3xx comes back as a plain response.
        },
        (res) => {
          const chunks: Buffer[] = [];
          let received = 0;
          let truncated = false;
          res.on("data", (chunk: Buffer) => {
            received += chunk.length;
            if (received <= this.limits.maxResponseBytes) {
              chunks.push(chunk);
            } else {
              // Keep only the capped prefix; drain the rest without storing.
              truncated = true;
              const room = this.limits.maxResponseBytes - (received - chunk.length);
              if (room > 0) chunks.push(chunk.subarray(0, room));
            }
          });
          res.on("error", () => reject(new ProbeNetworkError("response stream error")));
          res.on("end", () => {
            const body = Buffer.concat(chunks);
            resolve({
              status: res.statusCode ?? 0,
              headers: res.headers,
              bodyBytes: received,
              bodyTruncated: truncated,
              bodyHash: sha256Hex(body),
            });
          });
        },
      );
      request.setTimeout(this.limits.timeoutMs, () => {
        request.destroy(
          new ProbeNetworkError(`request timed out after ${this.limits.timeoutMs}ms`),
        );
      });
      request.on("error", (err) => {
        reject(
          err instanceof ProbeNetworkError
            ? err
            : new ProbeNetworkError(`request failed: ${err.message}`),
        );
      });
      request.end();
    });
  }
}

/**
 * Recompute an evidence artifact's redaction safety: true when no sensitive
 * request-header value survived sanitization. A guard for tests and a future
 * artifact validator.
 */
export function evidenceIsSanitized(evidence: LiveEvidence, secrets: readonly string[]): boolean {
  const serialized = JSON.stringify(evidence);
  for (const secret of secrets) {
    if (secret.length > 0 && serialized.includes(secret)) return false;
  }
  for (const obs of evidence.observations) {
    for (const [name, value] of Object.entries(obs.request.headerValues)) {
      if (sensitiveRequestHeaders().has(name) && value !== REDACTED) return false;
    }
  }
  return true;
}

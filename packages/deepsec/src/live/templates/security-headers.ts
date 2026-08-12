import type { AssertionOutcome, LiveTestPlan, LiveVerdict, ProbeObservation } from "@deepsec/core";
import type { ProbeRunner } from "../probe.js";

// ---------------------------------------------------------------------------
// Deterministic template: security-header posture (Milestone 1).
//
// One passive GET of the route; assertions over response headers only.
// Deterministic templates use no model adjudication — typed assertions are
// the verdict (plans/live-investigations.md, "Shared knowledge").
// ---------------------------------------------------------------------------

export const SECURITY_HEADERS_TEMPLATE_ID = "security-headers";

/**
 * The headers this template asserts on, in stable order. Each missing header
 * is a distinct assertion outcome so evidence pinpoints exactly what is weak.
 */
export const EXPECTED_SECURITY_HEADERS = [
  "x-content-type-options",
  "x-frame-options",
  "content-security-policy",
  "strict-transport-security",
] as const;

export interface SecurityHeadersOutcome {
  observations: ProbeObservation[];
  assertions: AssertionOutcome[];
  verdict: LiveVerdict;
  reasoning: string;
}

function headerValue(obs: ProbeObservation, name: string): string | undefined {
  const value = obs.headers[name.toLowerCase()];
  return typeof value === "string" && value.trim() !== "" ? value : undefined;
}

/**
 * Adjudicate one observation: every expected header must be present.
 * - all present  -> each assertion passes; verdict `not-observed` (the header
 *   weakness this template looks for was not observed)
 * - some missing -> those assertions fail; verdict `confirmed`
 * - no/ambiguous response (0 status from a transport oddity) -> `inconclusive`
 */
export function adjudicateSecurityHeaders(observation: ProbeObservation): {
  assertions: AssertionOutcome[];
  verdict: LiveVerdict;
} {
  const assertions: AssertionOutcome[] = EXPECTED_SECURITY_HEADERS.map((name) => {
    const present = headerValue(observation, name) !== undefined;
    return {
      assertionId: `header-present:${name}`,
      outcome: present ? ("pass" as const) : ("fail" as const),
      detail: present ? `${name} is set` : `${name} is missing on a ${observation.status} response`,
    };
  });

  if (observation.status === 0) {
    return {
      assertions: assertions.map((a) => ({ ...a, outcome: "inconclusive" as const })),
      verdict: "inconclusive",
    };
  }

  const anyMissing = assertions.some((a) => a.outcome === "fail");
  return { assertions, verdict: anyMissing ? "confirmed" : "not-observed" };
}

/**
 * Run the template: GET the plan's route and assert on its response headers.
 * Budget, origin, method, path, and rate policy are all enforced by the
 * ProbeRunner; this function only sequences probe + adjudication.
 */
export async function runSecurityHeadersTemplate(
  runner: ProbeRunner,
  plan: LiveTestPlan,
): Promise<SecurityHeadersOutcome> {
  const observation = await runner.request(
    {
      unitRef: plan.id,
      method: "GET",
      path: plan.route,
      headers: plan.headers,
      purpose: `security-header posture check of ${plan.route}`,
    },
    0,
  );

  const { assertions, verdict } = adjudicateSecurityHeaders(observation);
  const missing = assertions
    .filter((a) => a.outcome === "fail")
    .map((a) => a.assertionId.replace("header-present:", ""));

  const reasoning =
    verdict === "confirmed"
      ? `Missing security header(s) on ${plan.route}: ${missing.join(", ")}`
      : verdict === "not-observed"
        ? `All expected security headers are present on ${plan.route}`
        : `No usable response from ${plan.route} (status ${observation.status})`;

  return { observations: [observation], assertions, verdict, reasoning };
}

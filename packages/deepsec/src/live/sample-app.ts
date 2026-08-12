import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { LiveVerdict } from "@deepsec/core";

// ---------------------------------------------------------------------------
// Helpers for exercising the live templates against fixtures/sample-app.
//
// The fixture ships a machine-readable ground-truth manifest
// (expectations.json); the sample-app runner (fixtures/sample-app/run-m1.mjs)
// starts server.mjs on an ephemeral port, runs the M1 template set, and
// compares verdicts against this manifest. Lives in packages/deepsec so the
// path and types are typechecked, though the runner itself is plain node.
// ---------------------------------------------------------------------------

export interface SampleAppExpectation {
  route: string;
  method: string;
  behavior: string;
  authExpectation: string;
  templates: Record<string, string>;
  note?: string;
}

export interface SampleAppExpectations {
  version: number;
  description: string;
  identities: Record<string, string | null>;
  expectations: SampleAppExpectation[];
}

export interface SampleAppVerdictComparison {
  route: string;
  template: string;
  expected: string;
  actual: LiveVerdict;
  match: boolean;
}

/** Absolute path to fixtures/sample-app (repo root is three levels up). */
export function sampleAppDir(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  // src/live -> src -> packages/deepsec -> packages -> <repo root>
  return path.resolve(here, "..", "..", "..", "..", "fixtures", "sample-app");
}

export function sampleAppServerPath(): string {
  return path.join(sampleAppDir(), "server.mjs");
}

export function loadSampleAppExpectations(): SampleAppExpectations {
  const p = path.join(sampleAppDir(), "expectations.json");
  return JSON.parse(fs.readFileSync(p, "utf-8")) as SampleAppExpectations;
}

/**
 * Compare executed verdicts (keyed `${route} ${template}`) against the
 * manifest. Only templates the manifest names are compared.
 */
export function compareWithExpectations(
  expectations: SampleAppExpectations,
  actual: ReadonlyMap<string, LiveVerdict>,
): SampleAppVerdictComparison[] {
  const comparisons: SampleAppVerdictComparison[] = [];
  for (const exp of expectations.expectations) {
    for (const [template, expected] of Object.entries(exp.templates)) {
      const key = `${exp.route} ${template}`;
      const got = actual.get(key);
      if (got === undefined) continue; // template not part of this run
      comparisons.push({
        route: exp.route,
        template,
        expected,
        actual: got,
        match: got === expected,
      });
    }
  }
  return comparisons;
}

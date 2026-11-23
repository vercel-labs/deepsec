import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const CLI_PATH = fileURLToPath(new URL("../cli.ts", import.meta.url));
const REPO_ROOT = fileURLToPath(new URL("../../../../", import.meta.url));

function runCli(args: string[]) {
  return spawnSync(process.execPath, ["--import", "tsx", CLI_PATH, ...args], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    timeout: 120_000,
  });
}

function describeResult(result: ReturnType<typeof runCli>): string {
  return `status=${result.status}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`;
}

// `process` and `revalidate` advertise `--model-auth custom`, but the route
// builder rejects custom mode unless `--ai-credential-header` is present.
// Run the real CLI entry point so a missing Commander option fails here as
// "unknown option" instead of for users. The missing-value case also proves
// the option is registered with a required argument rather than swallowed.
describe("run commands accept --ai-credential-header", () => {
  for (const command of ["process", "revalidate"] as const) {
    it(`${command} --help lists --ai-credential-header`, () => {
      const result = runCli([command, "--help"]);
      expect(result.status, describeResult(result)).toBe(0);
      expect(result.stdout).toContain("--ai-credential-header <name[:scheme]>");
      expect(result.stdout).toContain("scheme is bearer or raw");
    }, 120_000);

    it(`${command} parses --ai-credential-header as a value option`, () => {
      const result = runCli([command, "--ai-credential-header"]);
      expect(result.status, describeResult(result)).toBe(1);
      expect(result.stderr).toContain(
        "error: option '--ai-credential-header <name[:scheme]>' argument missing",
      );
    }, 120_000);
  }
});

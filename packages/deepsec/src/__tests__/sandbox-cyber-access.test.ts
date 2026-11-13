import { describe, expect, it } from "vitest";
import { rejectCyberAccessProgram } from "../commands/sandbox-process.js";

describe("rejectCyberAccessProgram", () => {
  it("rejects the flag in both spellings", () => {
    const message =
      "--cyber-access-program needs Codex subscription auth, which sandbox workers don't have. Run process or revalidate locally instead.";
    expect(() => rejectCyberAccessProgram(["--cyber-access-program", "daybreak_blue"])).toThrow(
      message,
    );
    expect(() => rejectCyberAccessProgram(["--cyber-access-program=daybreak_blue"])).toThrow(
      message,
    );
  });

  it("allows passthrough args without the flag", () => {
    expect(() => rejectCyberAccessProgram(["--agent", "codex", "--limit", "5"])).not.toThrow();
  });
});

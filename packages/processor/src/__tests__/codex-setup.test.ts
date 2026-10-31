import { describe, expect, it } from "vitest";
import { finalizeCodexSetupResult } from "../agents/codex-sdk.js";
import { QuotaExhaustedError } from "../agents/shared.js";

describe("Codex setup result", () => {
  it("does not accept partial output after the turn fails", () => {
    expect(() => finalizeCodexSetupResult(["partial JSON"], "Codex setup turn failed")).toThrow(
      "Codex setup turn failed",
    );
  });

  it("classifies setup quota failures", () => {
    expect(() => finalizeCodexSetupResult(["partial JSON"], "You've hit your usage limit")).toThrow(
      QuotaExhaustedError,
    );
  });
});

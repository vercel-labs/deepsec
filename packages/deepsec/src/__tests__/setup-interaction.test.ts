import { describe, expect, it } from "vitest";
import { shouldUseHeadlessMode } from "../setup/interaction.js";

describe("setup interaction mode", () => {
  it("uses interactive mode only when both streams are TTYs", () => {
    expect(shouldUseHeadlessMode({}, { stdinIsTTY: true, stdoutIsTTY: true })).toBe(false);
    expect(shouldUseHeadlessMode({}, { stdinIsTTY: false, stdoutIsTTY: true })).toBe(true);
    expect(shouldUseHeadlessMode({}, { stdinIsTTY: true, stdoutIsTTY: false })).toBe(true);
  });

  it("honors either explicit headless spelling in a TTY", () => {
    const tty = { stdinIsTTY: true, stdoutIsTTY: true };
    expect(shouldUseHeadlessMode({ headless: true }, tty)).toBe(true);
    expect(shouldUseHeadlessMode({ nonInteractive: true }, tty)).toBe(true);
  });
});

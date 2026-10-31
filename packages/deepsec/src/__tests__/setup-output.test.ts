import { describe, expect, it, vi } from "vitest";
import {
  createTerminalLineDecoder,
  normalizeTerminalLine,
  packageInstallProgress,
} from "../setup/output.js";

describe("setup output normalization", () => {
  it("turns CR progress updates into clean lines and preserves split UTF-8", () => {
    const onLine = vi.fn();
    const decoder = createTerminalLineDecoder(onLine);
    const bytes = Buffer.from("Progress: added 1\rProgress: added 2\n✓ café");

    decoder.write(bytes.subarray(0, bytes.length - 1));
    decoder.write(bytes.subarray(bytes.length - 1));
    decoder.end();

    expect(onLine.mock.calls.map(([line]) => line)).toEqual([
      "Progress: added 1",
      "Progress: added 2",
      "✓ café",
    ]);
  });

  it("removes terminal control sequences and caps pathological lines", () => {
    expect(normalizeTerminalLine("\u001B[32mDone\u001B[0m\u0008")).toBe("Done");
    expect(normalizeTerminalLine("x".repeat(20), 5)).toBe("xxxxx… [truncated]");
  });

  it("extracts package counts without exposing raw package-manager output", () => {
    expect(packageInstallProgress("Packages: +286")).toEqual({ expectedPackages: 286 });
    expect(packageInstallProgress("Progress: resolved 306, reused 286, added 157", 286)).toEqual({
      current: 157,
      total: 286,
      expectedPackages: 286,
    });
  });
});

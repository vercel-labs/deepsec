import { describe, expect, it } from "vitest";
import { capStream } from "../output-cap.js";

function makeSink() {
  const written: string[] = [];
  return {
    written,
    stream: {
      write(chunk: unknown, encoding?: unknown, callback?: unknown): boolean {
        if (typeof encoding === "function") {
          callback = encoding;
        }
        written.push(String(chunk));
        if (typeof callback === "function") (callback as () => void)();
        return true;
      },
    },
  };
}

describe("capStream", () => {
  it("passes short writes through untouched", () => {
    const { stream, written } = makeSink();
    capStream(stream, { remainingBytes: 1024, exhausted: false });
    stream.write("hello\n");
    expect(written).toEqual(["hello\n"]);
  });

  it("truncates individual long lines", () => {
    const { stream, written } = makeSink();
    capStream(stream, { remainingBytes: 1024 * 1024, exhausted: false });
    stream.write(`short\n${"x".repeat(5000)}\nend\n`);
    expect(written).toHaveLength(1);
    const lines = written[0].split("\n");
    expect(lines[0]).toBe("short");
    expect(lines[1]).toContain("[line truncated]");
    expect(lines[1].length).toBeLessThan(2100);
    expect(lines[2]).toBe("end");
  });

  it("suppresses output after the byte budget is exhausted", () => {
    const { stream, written } = makeSink();
    const state = { remainingBytes: 10, exhausted: false };
    capStream(stream, state);
    stream.write("0123456789ABC");
    expect(written[0]).toContain("output cap reached");
    stream.write("more\n");
    expect(written).toHaveLength(1);
    expect(state.exhausted).toBe(true);
  });

  it("shares one budget across two streams", () => {
    const out = makeSink();
    const err = makeSink();
    const state = { remainingBytes: 10, exhausted: false };
    capStream(out.stream, state);
    capStream(err.stream, state);
    out.stream.write("0123456789ABC");
    err.stream.write("never shown\n");
    expect(out.written).toHaveLength(1);
    expect(err.written).toHaveLength(0);
  });

  it("still invokes callbacks while suppressing", () => {
    const { stream } = makeSink();
    capStream(stream, { remainingBytes: 0, exhausted: true });
    let called = false;
    stream.write("dropped", () => {
      called = true;
    });
    expect(called).toBe(true);
  });

  it("decodes Buffer chunks", () => {
    const { stream, written } = makeSink();
    capStream(stream, { remainingBytes: 1024, exhausted: false });
    stream.write(Buffer.from("buf\n"));
    expect(written).toEqual(["buf\n"]);
  });
});

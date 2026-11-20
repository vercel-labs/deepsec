import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildFxAskArgs, buildFxSettings } from "../agents/fx-cli.js";

// Opt-in: runs a real fx binary (DEEPSEC_FX_E2E_BIN) with the backend's
// settings against a local fake model that asks for reads through
// repository symlinks pointing outside the project. fx resolves the real
// path before reading (src/core/workspace/pathing.zig), so the canary
// outside the project must never reach the model.
const FX_BIN = process.env.DEEPSEC_FX_E2E_BIN;
const CANARY = "OUTSIDE-CANARY-5d2e";

const ESCAPES: Array<[string, Record<string, string>]> = [
  ["read_file", { path: "link.txt" }],
  ["read_file", { path: "linkdir/outside.txt" }],
  // Search for part of the canary: grep echoes its pattern, so only real file
  // contents can contain the whole canary.
  ["grep_files", { pattern: "CANARY" }],
  ["grep_files", { pattern: "CANARY", path: "linkdir" }],
  ["glob_files", { pattern: "*", path: "linkdir" }],
  ["read_file", { path: "alias.txt" }],
];

describe.skipIf(!FX_BIN)("fx backend with repository symlinks (real fx)", () => {
  let dir: string;
  let server: Server;
  let port: number;
  const toolResults: string[][] = [];

  beforeAll(async () => {
    dir = mkdtempSync(path.join(tmpdir(), "deepsec-fx-symlinks-"));
    mkdirSync(path.join(dir, "project"));
    mkdirSync(path.join(dir, "outside"));
    writeFileSync(path.join(dir, "project", "inside.txt"), "INSIDE-OK\n");
    writeFileSync(path.join(dir, "outside", "outside.txt"), `${CANARY}\n`);
    symlinkSync("../outside/outside.txt", path.join(dir, "project", "link.txt"));
    symlinkSync("../outside", path.join(dir, "project", "linkdir"));
    symlinkSync("inside.txt", path.join(dir, "project", "alias.txt"));

    // OpenAI-compatible streaming stub: one tool call per request, then "[]".
    server = createServer(async (req, res) => {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      const results = (body.messages as Array<{ role: string; content: unknown }>)
        .filter((m) => m.role === "tool")
        .map((m) =>
          typeof m.content === "string"
            ? m.content
            : ((m.content as Array<{ text?: string }>) ?? []).map((p) => p.text ?? "").join(""),
        );
      toolResults.push(results);
      res.writeHead(200, { "Content-Type": "text/event-stream" });
      const send = (delta: unknown, finish: string | null) =>
        res.write(
          `data: ${JSON.stringify({ choices: [{ index: 0, delta, finish_reason: finish }] })}\n\n`,
        );
      const next = ESCAPES[results.length];
      if (next) {
        const [name, args] = next;
        send(
          {
            role: "assistant",
            tool_calls: [
              {
                index: 0,
                id: `c${results.length}`,
                type: "function",
                function: { name, arguments: JSON.stringify(args) },
              },
            ],
          },
          null,
        );
        send({}, "tool_calls");
      } else {
        send({ role: "assistant", content: "[]" }, null);
        send({}, "stop");
      }
      res.end("data: [DONE]\n\n");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    port = (server.address() as AddressInfo).port;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server?.close(() => resolve()));
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it("never returns file contents from outside the project", async () => {
    const cfg = { model: "stub/model", aiBaseUrl: `http://127.0.0.1:${port}/v1` };
    const home = path.join(dir, "home");
    mkdirSync(path.join(home, ".fx"), { recursive: true });
    writeFileSync(
      path.join(home, ".fx", "settings.json"),
      JSON.stringify(buildFxSettings(cfg), null, 2),
    );
    const child = spawn(FX_BIN as string, buildFxAskArgs(cfg, { maxTurns: 20 }), {
      cwd: path.join(dir, "project"),
      env: {
        HOME: home,
        PATH: process.env.PATH,
        FX_AUTO_UPGRADE: "0",
        FX_DISABLE_KEYCHAIN: "1",
        FX_SOUND: "0",
        NO_COLOR: "1",
      },
      stdio: ["pipe", "ignore", "ignore"],
    });
    child.stdin.end("Investigate the project.");
    const code = await new Promise<number | null>((resolve) => child.once("close", resolve));
    expect(code).toBe(0);

    const final = toolResults.at(-1) ?? [];
    expect(final).toHaveLength(ESCAPES.length);
    for (const result of final) expect(result).not.toContain(CANARY);
    // Escapes are refused; the in-project symlink resolves to its target.
    expect(final[0]).toContain("Path is outside the workspace");
    expect(final[1]).toContain("Path is outside the workspace");
    expect(final[3]).toContain("Path is outside the workspace");
    expect(final[4]).toContain("Path is outside the workspace");
    expect(final[5]).toContain("INSIDE-OK");
  }, 60_000);
});

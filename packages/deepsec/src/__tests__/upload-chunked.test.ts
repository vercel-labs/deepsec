import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { Sandbox } from "@vercel/sandbox";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { uploadTarballToSandbox } from "../sandbox/upload.js";

/**
 * Stand-in for a sandbox whose filesystem is a local temp directory.
 * `runCommand` executes the real command locally so the join script's
 * shell semantics are exercised.
 */
function localSandbox(overrides: { joinedBytes?: string } = {}) {
  const writes: { path: string; bytes: number }[] = [];
  const commands: { cmd: string; args: string[] }[] = [];
  const sandbox = {
    async writeFiles(files: { path: string; content: Uint8Array }[]) {
      for (const f of files) {
        fs.writeFileSync(f.path, f.content);
        writes.push({ path: f.path, bytes: f.content.length });
      }
    },
    async runCommand({ cmd, args }: { cmd: string; args: string[] }) {
      commands.push({ cmd, args });
      const r = spawnSync(cmd, args, { encoding: "utf8" });
      return {
        exitCode: r.status ?? 1,
        stdout: async () => overrides.joinedBytes ?? r.stdout,
        stderr: async () => r.stderr,
      };
    },
  };
  return { sandbox: sandbox as unknown as Sandbox, writes, commands };
}

describe("uploadTarballToSandbox", () => {
  let tmp: string;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-upload-chunks-"));
  });

  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  function localTarball(bytes: number): { file: string; content: Buffer } {
    const content = crypto.randomBytes(bytes);
    const file = path.join(tmp, "local.tar.gz");
    fs.writeFileSync(file, content);
    return { file, content };
  }

  it("sends a tarball at or under the chunk size in one write", async () => {
    const { file, content } = localTarball(1024);
    const remote = path.join(tmp, "remote.tar.gz");
    const { sandbox, writes, commands } = localSandbox();

    await uploadTarballToSandbox(sandbox, remote, file, undefined, { chunkBytes: 1024 });

    expect(writes).toEqual([{ path: remote, bytes: 1024 }]);
    expect(commands).toEqual([]);
    expect(fs.readFileSync(remote).equals(content)).toBe(true);
    expect(fs.existsSync(file)).toBe(false);
  });

  it("uploads a larger tarball in ordered parts and joins them on the sandbox", async () => {
    const { file, content } = localTarball(5000);
    const remote = path.join(tmp, "remote.tar.gz");
    const { sandbox, writes } = localSandbox();

    await uploadTarballToSandbox(sandbox, remote, file, undefined, { chunkBytes: 1024 });

    expect(writes.map((w) => path.basename(w.path))).toEqual([
      "remote.tar.gz.part-00000",
      "remote.tar.gz.part-00001",
      "remote.tar.gz.part-00002",
      "remote.tar.gz.part-00003",
      "remote.tar.gz.part-00004",
    ]);
    expect(writes.map((w) => w.bytes)).toEqual([1024, 1024, 1024, 1024, 904]);
    expect(fs.readFileSync(remote).equals(content)).toBe(true);
    expect(fs.readdirSync(tmp).filter((f) => f.includes(".part-"))).toEqual([]);
    expect(fs.existsSync(file)).toBe(false);
  });

  it("handles a tarball that is an exact multiple of the chunk size", async () => {
    const { file, content } = localTarball(3072);
    const remote = path.join(tmp, "remote.tar.gz");
    const { sandbox, writes } = localSandbox();

    await uploadTarballToSandbox(sandbox, remote, file, undefined, { chunkBytes: 1024 });

    expect(writes).toHaveLength(3);
    expect(fs.readFileSync(remote).equals(content)).toBe(true);
  });

  it("fails when the joined file size does not match the local tarball", async () => {
    const { file } = localTarball(3000);
    const remote = path.join(tmp, "remote.tar.gz");
    const { sandbox } = localSandbox({ joinedBytes: "2048\n" });

    await expect(
      uploadTarballToSandbox(sandbox, remote, file, undefined, { chunkBytes: 1024 }),
    ).rejects.toThrow("is 2048 bytes on the sandbox, expected 3000");
  });
});

import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseEnvFile, updateEnvFile } from "../env-file.js";

describe("env-file", () => {
  it("replaces selected values and preserves unrelated content", async () => {
    const dir = await mkdtemp(join(tmpdir(), "deepsec-env-"));
    const file = join(dir, ".env.local");
    await writeFile(file, "# keep me\nUNCHANGED = old # exact\nTOKEN=old\nexport TOKEN=older\n");
    await updateEnvFile(file, { TOKEN: "new value", ADDED: "line\nfeed" });
    const contents = await readFile(file, "utf8");
    expect(contents).toContain("# keep me\nUNCHANGED = old # exact\n");
    expect(contents).toContain('TOKEN="new value"');
    expect(contents).not.toContain("older");
    expect(parseEnvFile(contents)).toMatchObject({ TOKEN: "new value", ADDED: "line\nfeed" });
    expect((await stat(file)).mode & 0o777).toBe(0o600);
  });

  it("rejects invalid variable names", async () => {
    await expect(updateEnvFile("/tmp/unused", { "BAD-NAME": "x" })).rejects.toThrow(
      /Invalid environment variable/,
    );
  });
});

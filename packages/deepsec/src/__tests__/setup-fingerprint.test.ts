import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { listRepositoryFiles } from "../setup/fingerprint.js";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

describe("listRepositoryFiles", () => {
  it("prunes Rust build output from the setup fingerprint and coverage universe", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-fingerprint-"));
    roots.push(root);
    fs.mkdirSync(path.join(root, "src"));
    fs.mkdirSync(path.join(root, "target", "debug"), { recursive: true });
    fs.writeFileSync(path.join(root, "src", "main.rs"), "fn main() {}\n");
    fs.writeFileSync(path.join(root, "target", "debug", "generated.rs"), "build output\n");

    expect(listRepositoryFiles(root)).toEqual(["src/main.rs"]);
  });

  it("keeps real data source while ignoring only validated Deepsec data", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-fingerprint-"));
    roots.push(root);
    fs.mkdirSync(path.join(root, "data", "pipelines"), { recursive: true });
    fs.mkdirSync(path.join(root, "data", "app", "files"), { recursive: true });
    fs.writeFileSync(path.join(root, "data", "pipelines", "ingest.ts"), "export const GET = 1;\n");
    fs.writeFileSync(
      path.join(root, "data", "app", "project.json"),
      JSON.stringify({ projectId: "app", rootPath: root, createdAt: new Date().toISOString() }),
    );
    fs.writeFileSync(path.join(root, "data", "app", "files", "record.json"), "{}\n");

    expect(listRepositoryFiles(root)).toContain("data/pipelines/ingest.ts");
    expect(listRepositoryFiles(root)).not.toContain("data/app/files/record.json");
  });
});

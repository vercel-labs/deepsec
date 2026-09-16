import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { loadAllFileRecords } from "@deepsec/core";
import { afterEach, describe, expect, it } from "vitest";
import { detectTech } from "../detect-tech.js";
import { evaluateGate, scan } from "../index.js";
import { rbAsyncWebSocketHandlerMatcher } from "../matchers/rb-async-websocket-handler.js";
import { rbFalconRackAppMatcher } from "../matchers/rb-falcon-rack-app.js";
import { rbGrpcServiceMatcher } from "../matchers/rb-grpc-service.js";

let cleanups: Array<() => void> = [];

afterEach(() => {
  for (const cleanup of cleanups.reverse()) cleanup();
  cleanups = [];
});

function makeProject(files: Record<string, string>): { root: string; projectId: string } {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-ruby-async-"));
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-ruby-async-data-"));
  const previousDataRoot = process.env.DEEPSEC_DATA_ROOT;
  process.env.DEEPSEC_DATA_ROOT = dataRoot;

  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }

  const projectId = `ruby-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  cleanups.push(() => {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(dataRoot, { recursive: true, force: true });
    if (previousDataRoot === undefined) delete process.env.DEEPSEC_DATA_ROOT;
    else process.env.DEEPSEC_DATA_ROOT = previousDataRoot;
  });
  return { root, projectId };
}

describe("Ruby async matcher gates", () => {
  it("activates Ruby gRPC and websocket matchers from nested Gemfiles", () => {
    const { root } = makeProject({
      "apps/foo/Gemfile": `source "https://rubygems.org"\ngem "async-grpc"\ngem "async-websocket"\n`,
    });
    const detected = detectTech(root);

    expect(evaluateGate(rbGrpcServiceMatcher.requires, detected, root)).toBe(true);
    expect(evaluateGate(rbAsyncWebSocketHandlerMatcher.requires, detected, root)).toBe(true);
  });

  it("activates the Falcon matcher from nested Gemfiles and root config.ru", () => {
    let project = makeProject({
      "apps/foo/Gemfile": `source "https://rubygems.org"\ngem "falcon"\n`,
    });
    let detected = detectTech(project.root);
    expect(evaluateGate(rbFalconRackAppMatcher.requires, detected, project.root)).toBe(true);

    project = makeProject({
      "config.ru": `run App.new\n`,
    });
    detected = detectTech(project.root);
    expect(evaluateGate(rbFalconRackAppMatcher.requires, detected, project.root)).toBe(true);
  });
});

describe("Ruby async full scans", () => {
  it("creates Ruby service and proto records for root-detected async-grpc projects", async () => {
    const { root, projectId } = makeProject({
      Gemfile: `source "https://rubygems.org"\ngem "async-grpc"\ngem "falcon"\n`,
      "config.ru": `run App.new\n`,
      "proto/foo.proto": `syntax = "proto3";\nservice Example { rpc Lookup (LookupRequest) returns (LookupResponse); }\nmessage LookupRequest { string path = 1; }\nmessage LookupResponse { string value = 1; }\n`,
      "lib/example_service.rb": `
class ExampleService < ExampleGen::Service
  def lookup(request, call)
    BackendClient.new(request.path, call.metadata["authorization"]).run
  end
end
`,
    });

    const result = await scan({ projectId, root });
    expect(result.activeMatchers).toEqual(
      expect.arrayContaining(["rb-grpc-service", "proto-rpc-surface"]),
    );

    const records = loadAllFileRecords(projectId);
    const service = records.find((r) => r.filePath === "lib/example_service.rb");
    expect(service?.candidates.map((c) => c.vulnSlug)).toContain("rb-grpc-service");

    const proto = records.find((r) => r.filePath === "proto/foo.proto");
    expect(proto?.candidates.map((c) => c.vulnSlug)).toContain("proto-rpc-surface");
  });

  it("creates Ruby service records for nested async-grpc projects via sentinel gates", async () => {
    const { root, projectId } = makeProject({
      "apps/api/Gemfile": `source "https://rubygems.org"\ngem "async-grpc"\n`,
      "apps/api/lib/example_service.rb": `
class ExampleService < ExampleGen::Service
  def lookup(request, call)
    call.metadata["authorization"]
  end
end
`,
    });

    const result = await scan({ projectId, root });
    expect(result.activeMatchers).toContain("rb-grpc-service");

    const records = loadAllFileRecords(projectId);
    const service = records.find((r) => r.filePath === "apps/api/lib/example_service.rb");
    expect(service?.candidates.map((c) => c.vulnSlug)).toContain("rb-grpc-service");
  });

  it("counts .ru files as Ruby in language stats", async () => {
    const { root, projectId } = makeProject({
      "config.ru": `run App.new\n`,
    });

    const result = await scan({ projectId, root, matcherSlugs: ["xss"] });
    const ruby = result.languageStats.find((s) => s.language === "ruby");
    expect(ruby?.scannedFiles).toBe(1);
  });
});

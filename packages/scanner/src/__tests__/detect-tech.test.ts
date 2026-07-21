import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { detectTech } from "../detect-tech.js";
import { evaluateGate } from "../index.js";

let tmpRoot: string;

function write(rel: string, content: string) {
  const full = path.join(tmpRoot, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content);
}

beforeEach(() => {
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-detect-tech-"));
});

afterEach(() => {
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

describe("detectTech", () => {
  it("returns empty tags for a directory with no manifests", () => {
    const detected = detectTech(tmpRoot);
    expect(detected.tags).toEqual([]);
  });

  it("detects Next.js + React from package.json", () => {
    write(
      "package.json",
      JSON.stringify({
        dependencies: { next: "15.0.0", react: "19.0.0" },
      }),
    );
    const detected = detectTech(tmpRoot);
    expect(detected.tags).toContain("nextjs");
    expect(detected.tags).toContain("react");
    expect(detected.tags).toContain("node");
  });

  it("detects Express", () => {
    write("package.json", JSON.stringify({ dependencies: { express: "^4" } }));
    expect(detectTech(tmpRoot).tags).toContain("express");
  });

  it("detects NestJS via prefix scan", () => {
    write(
      "package.json",
      JSON.stringify({ dependencies: { "@nestjs/core": "^10", "@nestjs/common": "^10" } }),
    );
    expect(detectTech(tmpRoot).tags).toContain("nestjs");
  });

  it("detects Node tech from package.json workspaces", () => {
    write(
      "package.json",
      JSON.stringify({
        workspaces: ["apps/*", "packages/*"],
        catalog: {
          hono: "4.0.0",
          next: "15.0.0",
        },
      }),
    );
    write(
      "apps/web/package.json",
      JSON.stringify({ dependencies: { next: "catalog:", react: "catalog:" } }),
    );
    write(
      "apps/api/package.json",
      JSON.stringify({ dependencies: { hono: "catalog:", "drizzle-orm": "catalog:" } }),
    );
    write("node_modules/ignored/package.json", JSON.stringify({ dependencies: { express: "^4" } }));

    const tags = detectTech(tmpRoot).tags;
    expect(tags).toEqual(expect.arrayContaining(["node", "nextjs", "react", "hono", "drizzle"]));
    expect(tags).not.toContain("express");
  });

  it("does not treat package manager catalogs as dependency usage", () => {
    write(
      "package.json",
      JSON.stringify({
        workspaces: ["apps/*"],
        catalog: {
          next: "15.0.0",
          hono: "4.0.0",
        },
      }),
    );
    write("apps/web/package.json", JSON.stringify({ dependencies: { "@acme/ui": "workspace:*" } }));

    const tags = detectTech(tmpRoot).tags;
    expect(tags).toContain("node");
    expect(tags).not.toContain("nextjs");
    expect(tags).not.toContain("hono");
  });

  it("does not scan undeclared nested package manifests", () => {
    write("package.json", JSON.stringify({ dependencies: { "@acme/root": "1.0.0" } }));
    write("apps/web/package.json", JSON.stringify({ dependencies: { next: "15.0.0" } }));

    const tags = detectTech(tmpRoot).tags;
    expect(tags).toContain("node");
    expect(tags).not.toContain("nextjs");
  });

  it("detects Node tech from object-form package.json workspaces", () => {
    write("package.json", JSON.stringify({ workspaces: { packages: ["apps/*"] } }));
    write("apps/api/package.json", JSON.stringify({ dependencies: { fastify: "^5" } }));

    const tags = detectTech(tmpRoot).tags;
    expect(tags).toEqual(expect.arrayContaining(["node", "fastify"]));
  });

  it("detects Node tech from pnpm workspaces and honors excluded package globs", () => {
    write(
      "pnpm-workspace.yaml",
      `packages:
  - "apps/*"
  - "!apps/private"
`,
    );
    write("apps/web/package.json", JSON.stringify({ dependencies: { next: "15.0.0" } }));
    write("apps/private/package.json", JSON.stringify({ dependencies: { express: "^4" } }));

    const detected = detectTech(tmpRoot);
    expect(detected.tags).toEqual(expect.arrayContaining(["node", "nextjs"]));
    expect(detected.tags).not.toContain("express");
    expect(detected.sentinels).toContain("pnpm-workspace.yaml");
  });

  it("detects Next.js from next.config files", () => {
    write("package.json", JSON.stringify({ workspaces: ["apps/*"] }));
    write("apps/web/package.json", JSON.stringify({ name: "web" }));
    write("apps/web/next.config.ts", "export default {};\n");

    const tags = detectTech(tmpRoot).tags;
    expect(tags).toContain("node");
    expect(tags).toContain("nextjs");
  });

  it("detects Laravel via composer.json", () => {
    write(
      "composer.json",
      JSON.stringify({ require: { "laravel/framework": "^11", php: "^8.2" } }),
    );
    expect(detectTech(tmpRoot).tags).toContain("laravel");
    expect(detectTech(tmpRoot).tags).toContain("php");
  });

  it("does not flag PHP-only repos as Laravel", () => {
    write("composer.json", JSON.stringify({ require: { "monolog/monolog": "^3" } }));
    const tags = detectTech(tmpRoot).tags;
    expect(tags).toContain("php");
    expect(tags).not.toContain("laravel");
  });

  it("detects Django via manage.py + requirements.txt", () => {
    write("manage.py", "#!/usr/bin/env python\n");
    write("requirements.txt", "Django==5.0\nrequests==2.32\n");
    const tags = detectTech(tmpRoot).tags;
    expect(tags).toContain("django");
    expect(tags).toContain("python");
  });

  it("detects FastAPI from pyproject.toml", () => {
    write("pyproject.toml", `[project]\nname = "x"\ndependencies = ["fastapi", "uvicorn"]\n`);
    expect(detectTech(tmpRoot).tags).toContain("fastapi");
  });

  it("detects Rails via Gemfile", () => {
    write("Gemfile", `source "https://rubygems.org"\ngem "rails", "~> 8.0"\n`);
    expect(detectTech(tmpRoot).tags).toContain("rails");
  });

  it("detects Gin from go.mod", () => {
    write("go.mod", `module example.com/x\n\nrequire (\n  github.com/gin-gonic/gin v1.10.0\n)\n`);
    const tags = detectTech(tmpRoot).tags;
    expect(tags).toContain("gin");
    expect(tags).toContain("go");
  });

  it("detects polyglot repos (Next.js + Django + Rails)", () => {
    write("apps/web/package.json", JSON.stringify({ dependencies: { next: "15.0.0" } }));
    write("package.json", JSON.stringify({ workspaces: ["apps/*"] }));
    write("manage.py", "");
    write("requirements.txt", "Django==5.0");
    write("Gemfile", `gem "rails"`);
    const tags = detectTech(tmpRoot).tags;
    expect(tags).toEqual(expect.arrayContaining(["nextjs", "django", "rails"]));
  });
});

describe("evaluateGate", () => {
  it("returns true when gate is undefined", () => {
    const detected = detectTech(tmpRoot);
    expect(evaluateGate(undefined, detected, tmpRoot)).toBe(true);
  });

  it("passes when a tech tag matches", () => {
    write("package.json", JSON.stringify({ dependencies: { express: "^4" } }));
    const detected = detectTech(tmpRoot);
    expect(evaluateGate({ tech: ["express"] }, detected, tmpRoot)).toBe(true);
    expect(evaluateGate({ tech: ["laravel"] }, detected, tmpRoot)).toBe(false);
  });

  it("passes when sentinelFiles + sentinelContains agree", () => {
    write("composer.json", JSON.stringify({ require: { "laravel/framework": "^11" } }));
    const detected = detectTech(tmpRoot);
    const gate = {
      sentinelFiles: ["composer.json"],
      sentinelContains: (_p: string, c: string) => c.includes("laravel/"),
    };
    expect(evaluateGate(gate, detected, tmpRoot)).toBe(true);
  });

  it("fails when sentinelContains rejects the match", () => {
    write("composer.json", JSON.stringify({ require: { "monolog/monolog": "^3" } }));
    const detected = detectTech(tmpRoot);
    const gate = {
      sentinelFiles: ["composer.json"],
      sentinelContains: (_p: string, c: string) => c.includes("laravel/"),
    };
    expect(evaluateGate(gate, detected, tmpRoot)).toBe(false);
  });

  it("treats tech and sentinelFiles as a union (either passes)", () => {
    write("composer.json", JSON.stringify({ require: { "laravel/framework": "^11" } }));
    const detected = detectTech(tmpRoot);
    // Tech wouldn't match "rails", but the sentinel still passes via the
    // contains predicate — gate returns true.
    expect(
      evaluateGate(
        {
          tech: ["rails"],
          sentinelFiles: ["composer.json"],
          sentinelContains: () => true,
        },
        detected,
        tmpRoot,
      ),
    ).toBe(true);
  });
});

describe("scan() honors every explicitly-requested matcher slug", () => {
  // Regression: when --matchers mixes a gated and an ungated slug on a
  // repo where the gated one's tech isn't detected, the ternary
  // `activeMatchers.length === 0 ? allSelected : activeMatchers` ran
  // only the ungated matcher and silently dropped the gated one. The
  // user explicitly named both — both must run.
  it("runs gated matchers when named via params.matcherSlugs", async () => {
    // Empty repo (no detected tech) so any tech-gated matcher would
    // normally be skipped.
    const { scan } = await import("../index.js");
    const root = tmpRoot;

    // Must register a project first; scan() calls ensureProject().
    const result = await scan({
      projectId: "matcher-honor-test",
      root,
      // Mix a tech-gated matcher (php-laravel-route requires laravel
      // tag, which this repo doesn't have) with an ungated one (xss).
      matcherSlugs: ["php-laravel-route", "xss"],
    });

    // Both should be active despite no Laravel detection.
    expect(result.activeMatchers).toEqual(expect.arrayContaining(["php-laravel-route", "xss"]));
    expect(result.skippedMatchers).not.toContain("php-laravel-route");

    // Cleanup the per-test data dir.
    const dataDir = path.resolve("data", "matcher-honor-test");
    if (fs.existsSync(dataDir)) {
      fs.rmSync(dataDir, { recursive: true });
    }
  });
});

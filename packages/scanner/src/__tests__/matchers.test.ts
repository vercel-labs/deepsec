import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { authBypassMatcher } from "../matchers/auth-bypass.js";
import { insecureCryptoMatcher } from "../matchers/insecure-crypto.js";
import { serverActionMatcher } from "../matchers/js-nextjs-server-action.js";
import { serverActionNoAuthMatcher } from "../matchers/js-nextjs-server-action-no-auth.js";
import { allServerActionsMatcher } from "../matchers/js-nextjs-server-actions.js";
import { missingAuthMatcher } from "../matchers/missing-auth.js";
import { openRedirectMatcher } from "../matchers/open-redirect.js";
import { pathTraversalMatcher } from "../matchers/path-traversal.js";
import { rceMatcher } from "../matchers/rce.js";
import { secretsExposureMatcher } from "../matchers/secrets-exposure.js";
import { sqlInjectionMatcher } from "../matchers/sql-injection.js";
import { ssrfMatcher } from "../matchers/ssrf.js";
import { hasFileDirective } from "../matchers/utils.js";
import { xssMatcher } from "../matchers/xss.js";

const FIXTURES_ROOT = path.resolve(import.meta.dirname, "../../../../fixtures/vulnerable-app/src");

function readFixture(relativePath: string): string {
  return fs.readFileSync(path.join(FIXTURES_ROOT, relativePath), "utf-8");
}

describe("auth-bypass matcher", () => {
  it("detects auth patterns in admin.ts", () => {
    const content = readFixture("api/admin.ts");
    const matches = authBypassMatcher.match(content, "src/api/admin.ts");
    expect(matches.length).toBeGreaterThan(0);
    expect(matches.some((m) => m.vulnSlug === "auth-bypass")).toBe(true);
  });
});

describe("missing-auth matcher", () => {
  it("flags all HTTP entry points in users.ts as weak candidates", () => {
    const content = readFixture("api/users.ts");
    const matches = missingAuthMatcher.match(content, "src/api/users.ts");
    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0].vulnSlug).toBe("missing-auth");
    expect(matches[0].matchedPattern).toContain("weak candidate");
  });

  it("also flags admin.ts — all entry points are candidates", () => {
    const content = readFixture("api/admin.ts");
    const matches = missingAuthMatcher.match(content, "src/api/admin.ts");
    // Now flags all entry points regardless of auth presence
    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0].matchedPattern).toContain("weak candidate");
  });

  it("does not flag non-handler files", () => {
    const content = readFixture("lib/db.ts");
    const matches = missingAuthMatcher.match(content, "src/lib/db.ts");
    expect(matches.length).toBe(0);
  });
});

describe("xss matcher", () => {
  it("detects dangerouslySetInnerHTML", () => {
    const content = readFixture("components/comment.tsx");
    const matches = xssMatcher.match(content, "src/components/comment.tsx");
    expect(matches.length).toBeGreaterThan(0);
    const slugs = matches.map((m) => m.matchedPattern);
    expect(slugs).toContain("dangerouslySetInnerHTML");
  });
});

describe("rce matcher", () => {
  it("detects exec/eval patterns", () => {
    const content = readFixture("utils/exec-helper.ts");
    const matches = rceMatcher.match(content, "src/utils/exec-helper.ts");
    expect(matches.length).toBeGreaterThan(0);
    const patterns = matches.map((m) => m.matchedPattern);
    expect(patterns.some((p) => p.includes("exec") || p.includes("eval"))).toBe(true);
  });
});

describe("sql-injection matcher", () => {
  it("detects interpolated SQL", () => {
    const content = readFixture("lib/db.ts");
    const matches = sqlInjectionMatcher.match(content, "src/lib/db.ts");
    expect(matches.length).toBeGreaterThan(0);
  });
});

describe("ssrf matcher", () => {
  it("detects fetch with user-controlled URL", () => {
    const content = readFixture("lib/fetch-proxy.ts");
    const matches = ssrfMatcher.match(content, "src/lib/fetch-proxy.ts");
    expect(matches.length).toBeGreaterThan(0);
  });
});

describe("path-traversal matcher", () => {
  it("detects file operations with user input", () => {
    const content = readFixture("api/upload.ts");
    const matches = pathTraversalMatcher.match(content, "src/api/upload.ts");
    expect(matches.length).toBeGreaterThan(0);
  });
});

describe("secrets-exposure matcher", () => {
  it("detects hardcoded secrets", () => {
    const content = readFixture("config.ts");
    const matches = secretsExposureMatcher.match(content, "src/config.ts");
    expect(matches.length).toBeGreaterThan(0);
  });
});

describe("insecure-crypto matcher", () => {
  it("detects MD5 and Math.random", () => {
    const content = readFixture("lib/crypto.ts");
    const matches = insecureCryptoMatcher.match(content, "src/lib/crypto.ts");
    expect(matches.length).toBeGreaterThan(0);
    const patterns = matches.map((m) => m.matchedPattern);
    expect(patterns.some((p) => p.includes("MD5"))).toBe(true);
    expect(patterns.some((p) => p.includes("Math.random"))).toBe(true);
  });
});

describe("open-redirect matcher", () => {
  it("detects redirect with user input", () => {
    const content = readFixture("utils/redirect.ts");
    const matches = openRedirectMatcher.match(content, "src/utils/redirect.ts");
    expect(matches.length).toBeGreaterThan(0);
  });
});

describe("hasFileDirective", () => {
  it("matches a bare directive at the start of the file", () => {
    expect(hasFileDirective(`"use server";\nexport async function f() {}`, "use server")).toBe(
      true,
    );
  });

  it("matches after a block-comment banner", () => {
    expect(hasFileDirective(`/* Copyright 2024 */\n"use server";`, "use server")).toBe(true);
  });

  it("matches after a JSDoc banner", () => {
    expect(hasFileDirective(`/**\n * @license MIT\n */\n"use server";`, "use server")).toBe(true);
  });

  it("matches after a line-comment header", () => {
    expect(hasFileDirective(`// internal\n"use server";`, "use server")).toBe(true);
  });

  it("matches after a shebang", () => {
    expect(hasFileDirective(`#!/usr/bin/env node\n"use server";`, "use server")).toBe(true);
  });

  it("matches single-quoted directives", () => {
    expect(hasFileDirective(`/* x */\n'use server';`, "use server")).toBe(true);
  });

  it("does not match when the directive only appears inside a comment", () => {
    expect(
      hasFileDirective(`// "use server" is set elsewhere\nexport function f() {}`, "use server"),
    ).toBe(false);
  });

  it("does not match when there is no directive at all", () => {
    expect(hasFileDirective(`export function f() {}`, "use server")).toBe(false);
  });

  it("respects the requested directive name", () => {
    expect(hasFileDirective(`/* x */\n"use client";`, "use client")).toBe(true);
    expect(hasFileDirective(`/* x */\n"use client";`, "use server")).toBe(false);
  });
});

describe("server-action matcher", () => {
  it("detects exports after a leading copyright banner", () => {
    const content = `/* Copyright 2024 Acme Corp. Apache 2.0 license. */
"use server";

export async function deleteAccount(userId: string) {
  return userId;
}`;
    const matches = serverActionMatcher.match(content, "src/app/actions.ts");
    expect(matches.length).toBe(1);
    expect(matches[0].vulnSlug).toBe("server-action");
    expect(matches[0].matchedPattern).toContain("file-level");
  });
});

describe("server-action-no-auth matcher", () => {
  it("flags banner-prefixed files with no auth call", () => {
    const content = `// internal helpers, see SECURITY.md
"use server";

export async function transferFunds(amount: number) {
  return amount;
}`;
    const matches = serverActionNoAuthMatcher.match(content, "src/app/actions.ts");
    expect(matches.length).toBe(1);
    expect(matches[0].matchedPattern).toContain("WITHOUT any auth call");
  });
});

describe("all-server-actions matcher", () => {
  it("flags every export in a file with a banner-prefixed file-level directive", () => {
    const content = `/**
 * @license MIT
 */
"use server";

export async function a() {}
export async function b() {}
export const c = async () => {};`;
    const matches = allServerActionsMatcher.match(content, "src/app/actions.ts");
    expect(matches.length).toBe(3);
  });
});

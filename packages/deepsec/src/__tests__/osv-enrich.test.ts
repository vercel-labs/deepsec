import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  buildContext,
  extractReachabilityBlock,
  findManifest,
  findManifests,
  findPom,
  manifestHasDirectRefs,
  mergeInfoWithOsvContext,
  OSV_CONTEXT_HEADING,
  parseOsv,
  spliceReachabilityBlock,
} from "../setup/osv-enrich.js";

// osv-scanner's JSON groups packages under results[].packages[], each result
// tagged with a source lockfile path, each package carrying vulnerabilities[]
// of {id, summary}.
const SAMPLE = JSON.stringify({
  results: [
    {
      source: { path: "requirements.txt", type: "lockfile" },
      packages: [
        {
          package: { name: "idna", version: "2.8", ecosystem: "PyPI" },
          vulnerabilities: [
            { id: "PYSEC-2024-60", summary: "idna ReDoS on long domain labels" },
            { id: "GHSA-65pc-fj4g-8rjx", details: "Denial of service via idna.encode()" },
          ],
        },
        {
          // clean dependency: no vulnerabilities, must be dropped
          package: { name: "click", version: "8.1.7", ecosystem: "PyPI" },
          vulnerabilities: [],
        },
      ],
    },
    {
      // deepsec's own workspace deps — vendored path, must be dropped entirely
      source: { path: ".deepsec/node_modules/.package-lock.json", type: "lockfile" },
      packages: [
        {
          package: { name: "undici", version: "8.5.0", ecosystem: "npm" },
          vulnerabilities: [{ id: "GHSA-2gqq-gqf2-x968", summary: "unrelated node dep" }],
        },
      ],
    },
  ],
});

describe("parseOsv", () => {
  it("extracts vulnerable packages with advisory summaries", () => {
    const hits = parseOsv(SAMPLE);
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ name: "idna", version: "2.8", ecosystem: "PyPI" });
    expect(hits[0].vulns).toEqual([
      { id: "PYSEC-2024-60", summary: "idna ReDoS on long domain labels" },
      { id: "GHSA-65pc-fj4g-8rjx", summary: "Denial of service via idna.encode()" },
    ]);
  });

  it("drops vendored sources (.deepsec / node_modules)", () => {
    const names = parseOsv(SAMPLE).map((h) => h.name);
    expect(names).not.toContain("undici");
  });

  it("returns nothing for empty or non-JSON output (osv missing / no sources)", () => {
    expect(parseOsv("")).toEqual([]);
    expect(parseOsv("No package sources found")).toEqual([]);
  });

  it("dedupes a package seen from two sources, merging unique advisories", () => {
    // Same Maven dep from osv's pom.xml parse AND the syft SBOM.
    const raw = JSON.stringify({
      results: [
        {
          source: { path: "pom.xml" },
          packages: [
            {
              package: { name: "log4j-core", version: "2.14.1", ecosystem: "Maven" },
              vulnerabilities: [{ id: "GHSA-jfh8-c2jp-5v3q" }],
            },
          ],
        },
        {
          source: { path: "/tmp/x/deps.cdx.json" },
          packages: [
            {
              package: { name: "log4j-core", version: "2.14.1", ecosystem: "Maven" },
              vulnerabilities: [{ id: "GHSA-jfh8-c2jp-5v3q" }, { id: "GHSA-7rjr-3q55-vv33" }],
            },
          ],
        },
      ],
    });
    const hits = parseOsv(raw);
    expect(hits).toHaveLength(1);
    expect(hits[0].vulns.map((v) => v.id)).toEqual(["GHSA-jfh8-c2jp-5v3q", "GHSA-7rjr-3q55-vv33"]);
  });
});

describe("parseOsv field sanitization (prompt-injection defense)", () => {
  it("collapses newlines/markdown in attacker-controlled name and version", () => {
    const raw = JSON.stringify({
      results: [
        {
          source: { path: "requirements.txt" },
          packages: [
            {
              package: {
                name: "evil\n## Injected heading\n- bullet",
                version: "1.0\n\nmore",
                ecosystem: "PyPI",
              },
              vulnerabilities: [{ id: "CVE-1", summary: "x" }],
            },
          ],
        },
      ],
    });
    const hits = parseOsv(raw);
    expect(hits).toHaveLength(1);
    expect(hits[0].name).not.toContain("\n");
    expect(hits[0].version).not.toContain("\n");
    // and the rendered prompt block carries no injected newlines from those fields
    const ctx = buildContext(hits);
    expect(ctx).toContain("Injected heading"); // present, but inline — not a real heading
    expect(ctx).not.toMatch(/\n##? Injected heading/);
  });
});

describe("findManifest", () => {
  it("finds a nested pyproject.toml but skips vendored and hidden trees", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-manifest-"));
    try {
      // A decoy inside a vendored tree must not be picked.
      fs.mkdirSync(path.join(root, "node_modules", "dep"), { recursive: true });
      fs.writeFileSync(path.join(root, "node_modules", "dep", "pyproject.toml"), "");
      fs.mkdirSync(path.join(root, "src", "pkg"), { recursive: true });
      const real = path.join(root, "src", "pkg", "pyproject.toml");
      fs.writeFileSync(real, "[project]\nname='x'\n");

      expect(findManifest(root)).toBe(real);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it("returns undefined when there is no manifest", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-manifest-"));
    try {
      expect(findManifest(root)).toBeUndefined();
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

describe("findManifests (monorepo)", () => {
  it("returns every pyproject.toml, not just the first", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-multi-"));
    try {
      fs.mkdirSync(path.join(root, "pkg-a"), { recursive: true });
      fs.mkdirSync(path.join(root, "pkg-b"), { recursive: true });
      fs.writeFileSync(path.join(root, "pkg-a", "pyproject.toml"), "");
      fs.writeFileSync(path.join(root, "pkg-b", "pyproject.toml"), "");
      const found = findManifests(root);
      expect(found).toHaveLength(2);
      expect(findManifest(root)).toBe(found[0]); // single-use helper returns the first
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

describe("findPom", () => {
  it("finds a nested pom.xml but skips vendored trees", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-pom-"));
    try {
      fs.mkdirSync(path.join(root, "vendor", "lib"), { recursive: true });
      fs.writeFileSync(path.join(root, "vendor", "lib", "pom.xml"), "");
      fs.mkdirSync(path.join(root, "server"), { recursive: true });
      const real = path.join(root, "server", "pom.xml");
      fs.writeFileSync(real, "<project></project>\n");

      expect(findPom(root)).toBe(real);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it("returns undefined when there is no pom", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-pom-"));
    try {
      expect(findPom(root)).toBeUndefined();
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

describe("manifestHasDirectRefs (SSRF guard)", () => {
  it("flags PEP 508 direct URL / VCS deps and leaves normal manifests alone", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-ref-"));
    try {
      const direct = path.join(root, "direct.toml");
      fs.writeFileSync(
        direct,
        '[project]\ndependencies = ["evil @ https://attacker.example/x.whl"]\n',
      );
      expect(manifestHasDirectRefs(direct)).toBe(true);

      const vcs = path.join(root, "vcs.toml");
      fs.writeFileSync(vcs, '[project]\ndependencies = ["pkg @ git+https://host/r.git"]\n');
      expect(manifestHasDirectRefs(vcs)).toBe(true);

      const normal = path.join(root, "normal.toml");
      fs.writeFileSync(normal, '[project]\ndependencies = ["requests>=2.0", "idna"]\n');
      expect(manifestHasDirectRefs(normal)).toBe(false);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

describe("buildContext resolved-version labeling", () => {
  it("marks resolved (hypothetical floor/ceiling) versions distinctly", () => {
    const ctx = buildContext([
      { name: "starlette", version: "0.46.0", vulns: [{ id: "X" }], resolved: true },
      { name: "log4j-core", version: "2.14.1", vulns: [{ id: "Y" }], resolved: false },
    ]);
    expect(ctx).toMatch(/`starlette@0\.46\.0` \(resolved range version/);
    expect(ctx).not.toMatch(/`log4j-core@2\.14\.1` \(resolved/);
  });

  it("emits the required graded reachability block naming every dependency", () => {
    const ctx = buildContext([
      { name: "starlette", version: "0.46.0", vulns: [{ id: "X" }], resolved: true },
      { name: "anyio", version: "3.6.2", vulns: [{ id: "Y" }], resolved: true },
      { name: "idna", version: "2.8.0", vulns: [{ id: "Z" }], resolved: true },
    ]);
    // the structured directive is present and demands a per-dep graded verdict
    expect(ctx).toContain("### Dependency reachability (required)");
    expect(ctx).toMatch(/HIGH\|MEDIUM\|LOW/);
    // every dependency is named in the directive so none can be silently dropped
    expect(ctx).toContain("`starlette`");
    expect(ctx).toContain("`anyio`");
    expect(ctx).toContain("`idna`");
  });

  it("flags a package as resolved via resolvedPaths", () => {
    const raw = JSON.stringify({
      results: [
        {
          source: { path: "/tmp/x/requirements.txt" },
          packages: [
            {
              package: { name: "starlette", version: "0.46.0", ecosystem: "PyPI" },
              vulnerabilities: [{ id: "PYSEC-1" }],
            },
          ],
        },
      ],
    });
    const hits = parseOsv(raw, new Set(["/tmp/x/requirements.txt"]));
    expect(hits[0].resolved).toBe(true);
  });
});

describe("mergeInfoWithOsvContext (no stale-section accumulation)", () => {
  const curated = "# proj\n\n## Threat model\ncurated content\n";
  const sectionA = `${OSV_CONTEXT_HEADING}\n\n- \`starlette@0.46.0\`\n  - CVE-OLD`;
  const sectionB = `${OSV_CONTEXT_HEADING}\n\n- \`anyio@4.0.0\`\n  - CVE-NEW`;

  it("replaces a previously appended section rather than accumulating", () => {
    const first = mergeInfoWithOsvContext(curated, sectionA);
    const second = mergeInfoWithOsvContext(first, sectionB);
    // exactly one advisory section, and it's the new one
    expect(
      second.match(new RegExp(OSV_CONTEXT_HEADING.replace(/[().]/g, "\\$&"), "g")),
    ).toHaveLength(1);
    expect(second).toContain("CVE-NEW");
    expect(second).not.toContain("CVE-OLD");
    expect(second).toContain("curated content"); // curated part preserved
  });

  it("drops the section entirely when there are no current advisories", () => {
    const withSection = mergeInfoWithOsvContext(curated, sectionA);
    const cleaned = mergeInfoWithOsvContext(withSection, "");
    expect(cleaned).not.toContain(OSV_CONTEXT_HEADING);
    expect(cleaned).toContain("curated content");
  });
});

describe("buildContext", () => {
  it("is empty when there are no vulnerable dependencies", () => {
    expect(buildContext([])).toBe("");
  });

  it("lists each advisory id with its summary so the ids are self-explanatory", () => {
    const ctx = buildContext([
      { name: "idna", version: "2.8", vulns: [{ id: "PYSEC-2024-60", summary: "ReDoS" }] },
    ]);
    expect(ctx).toContain("`idna@2.8`");
    expect(ctx).toContain("PYSEC-2024-60: ReDoS");
  });
});

describe("mergeInfoWithOsvContext (section boundaries)", () => {
  it("removes only the osv section, keeping curated sections that follow it", () => {
    const info = `# app\n\n## What this codebase does\nApp.\n\n${OSV_CONTEXT_HEADING}\n\n- \`x@1\`\n  - CVE-1\n\n## Threat model\nCurated threats.\n`;
    const out = mergeInfoWithOsvContext(info, "");
    expect(out).not.toContain(OSV_CONTEXT_HEADING);
    expect(out).not.toContain("CVE-1");
    expect(out).toContain("## Threat model\nCurated threats.");
    expect(out).toContain("## What this codebase does\nApp.");
  });
});

describe("dependency reachability splice", () => {
  const curated =
    "# app\n\n## Threat model\nCurated threats.\n\n## Project-specific patterns to flag\nRoutes.\n";
  const block =
    "### Dependency reachability\n- starlette@0.46.0 — HIGH reachability — r.py:1 — DoS";

  it("extracts the agent's block and stops at the next section", () => {
    const fresh = `# app\n\n## Threat model\nX.\n\n${block}\n\n## Project-specific patterns to flag\nY.\n`;
    expect(extractReachabilityBlock(fresh)).toBe(block);
    expect(extractReachabilityBlock(curated)).toBeUndefined();
  });

  it("inserts the block at the end of the Threat model section", () => {
    const out = spliceReachabilityBlock(curated, block);
    expect(out).toContain("Curated threats.");
    expect(out.indexOf("Curated threats.")).toBeLessThan(out.indexOf(block));
    expect(out.indexOf(block)).toBeLessThan(out.indexOf("## Project-specific patterns to flag"));
  });

  it("replaces a previous block instead of accumulating", () => {
    const once = spliceReachabilityBlock(curated, block);
    const newer =
      "### Dependency reachability\n- anyio@4.0.0 — LOW reachability — not called — n/a";
    const twice = spliceReachabilityBlock(once, newer);
    expect(twice.match(/### Dependency reachability/g)).toHaveLength(1);
    expect(twice).toContain("anyio@4.0.0");
    expect(twice).not.toContain("starlette@0.46.0");
  });

  it("removes stale verdicts when given no block", () => {
    const out = spliceReachabilityBlock(spliceReachabilityBlock(curated, block), undefined);
    expect(out).not.toContain("Dependency reachability");
    expect(out).toContain("## Project-specific patterns to flag\nRoutes.");
  });
});

describe("parseOsv vendored-tree filter", () => {
  const result = (p: string) => ({
    source: { path: p },
    packages: [
      {
        package: { name: "requests", version: "2.0.0", ecosystem: "PyPI" },
        vulnerabilities: [{ id: "CVE-X" }],
      },
    ],
  });

  it("does not drop a project that itself lives under a vendor/ directory", () => {
    const root = "/home/ci/vendor/acme-api";
    const raw = JSON.stringify({ results: [result(`${root}/requirements.txt`)] });
    expect(parseOsv(raw, undefined, root)).toHaveLength(1);
  });

  it("still drops vendored trees inside the project", () => {
    const root = "/home/ci/acme-api";
    const raw = JSON.stringify({
      results: [
        result(`${root}/node_modules/x/requirements.txt`),
        result(`${root}/.deepsec/a.txt`),
      ],
    });
    expect(parseOsv(raw, undefined, root)).toEqual([]);
  });

  it("keeps resolved lockfiles that live outside the project root", () => {
    const raw = JSON.stringify({ results: [result("/tmp/deepsec-osv-1/requirements.txt")] });
    expect(parseOsv(raw, undefined, "/home/ci/acme-api")).toHaveLength(1);
  });
});

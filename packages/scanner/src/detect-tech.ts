import fs from "node:fs";
import path from "node:path";
import { dataDir } from "@deepsec/core";

/**
 * Outcome of inspecting a project root for known tech. Tags are normalized
 * lowercase short names; sentinels carries the relative paths we found, so
 * matcher gates can reuse them without re-walking the tree.
 */
export interface DetectedTech {
  /** Lowercase short names: "nextjs", "django", "laravel", "rails", … */
  tags: string[];
  /** Relative paths (POSIX separators) of sentinel files we observed. */
  sentinels: string[];
  detectedAt: string;
  rootPath: string;
}

/** Read a file as utf-8, or null if missing/unreadable. Cached per call. */
function readSafe(rootPath: string, rel: string, cache: Map<string, string | null>): string | null {
  if (cache.has(rel)) return cache.get(rel) ?? null;
  try {
    const content = fs.readFileSync(path.join(rootPath, rel), "utf-8");
    cache.set(rel, content);
    return content;
  } catch {
    cache.set(rel, null);
    return null;
  }
}

function exists(rootPath: string, rel: string): boolean {
  try {
    return fs.existsSync(path.join(rootPath, rel));
  } catch {
    return false;
  }
}

/**
 * Quick directory glance — returns the immediate children of a root-relative
 * path, or [] if it doesn't exist. Used for "does this repo have a
 * routes/ dir?" checks without pulling in glob.
 */
function listDir(rootPath: string, rel: string): string[] {
  try {
    return fs.readdirSync(path.join(rootPath, rel));
  } catch {
    return [];
  }
}

/**
 * Detector signature: given the project root, the file-content cache, and
 * an existing tag set, return any new tags this detector wants to add.
 * Detectors are pure — they don't mutate state, the orchestrator does.
 */
type Detector = (rootPath: string, cache: Map<string, string | null>) => string[];

const detectors: Detector[] = [
  // --- Node / TS / JS ecosystems ---
  (root, cache) => {
    const pkg = readSafe(root, "package.json", cache);
    if (!pkg) return [];
    const tags: string[] = ["node"];
    let parsed: Record<string, unknown> | null = null;
    try {
      parsed = JSON.parse(pkg) as Record<string, unknown>;
    } catch {
      return tags;
    }
    const deps = {
      ...((parsed.dependencies as Record<string, string>) ?? {}),
      ...((parsed.devDependencies as Record<string, string>) ?? {}),
      ...((parsed.peerDependencies as Record<string, string>) ?? {}),
    };
    const has = (name: string) => Object.hasOwn(deps, name);
    const startsWith = (prefix: string) => Object.keys(deps).some((k) => k.startsWith(prefix));

    if (has("next")) tags.push("nextjs");
    if (has("react") || has("react-dom")) tags.push("react");
    if (has("express")) tags.push("express");
    if (has("fastify")) tags.push("fastify");
    if (startsWith("@nestjs/")) tags.push("nestjs");
    if (has("hono")) tags.push("hono");
    if (has("koa") || has("@koa/router")) tags.push("koa");
    if (has("@hapi/hapi")) tags.push("hapi");
    if (has("@remix-run/server-runtime") || has("@remix-run/node")) tags.push("remix");
    if (has("@sveltejs/kit")) tags.push("sveltekit");
    if (has("nuxt") || has("nuxt3") || has("h3")) tags.push("nuxt");
    if (has("astro")) tags.push("astro");
    if (has("@solidjs/start")) tags.push("solidstart");
    if (has("@trpc/server")) tags.push("trpc");
    if (has("@modelcontextprotocol/sdk")) tags.push("mcp");
    if (has("@connectrpc/connect")) tags.push("connectrpc");
    if (has("graphql") || has("apollo-server") || startsWith("@apollo/")) tags.push("graphql");
    if (has("socket.io")) tags.push("socketio");
    if (has("bullmq")) tags.push("bullmq");
    if (has("drizzle-orm")) tags.push("drizzle");
    if (has("@prisma/client") || has("prisma")) tags.push("prisma");
    return tags;
  },

  // --- Bun / Deno / Workers ---
  (root) => {
    const tags: string[] = [];
    if (exists(root, "bun.lockb") || exists(root, "bun.lock")) tags.push("bun");
    if (exists(root, "deno.json") || exists(root, "deno.jsonc") || exists(root, "deno.lock"))
      tags.push("deno");
    if (exists(root, "wrangler.toml") || exists(root, "wrangler.jsonc")) tags.push("workers");
    return tags;
  },

  // --- PHP ---
  (root, cache) => {
    if (!exists(root, "composer.json")) return [];
    const composer = readSafe(root, "composer.json", cache);
    const tags: string[] = ["php"];
    if (!composer) return tags;
    let parsed: Record<string, unknown> | null = null;
    try {
      parsed = JSON.parse(composer) as Record<string, unknown>;
    } catch {
      return tags;
    }
    const deps = {
      ...((parsed.require as Record<string, string>) ?? {}),
      ...((parsed["require-dev"] as Record<string, string>) ?? {}),
    };
    const keys = Object.keys(deps);
    if (keys.some((k) => k.startsWith("laravel/")) || exists(root, "artisan")) tags.push("laravel");
    if (keys.some((k) => k.startsWith("symfony/"))) tags.push("symfony");
    if (keys.includes("slim/slim")) tags.push("slim");
    if (keys.some((k) => k === "yiisoft/yii2" || k.startsWith("yiisoft/"))) tags.push("yii");
    if (keys.includes("cakephp/cakephp")) tags.push("cakephp");
    if (keys.includes("codeigniter4/framework")) tags.push("codeigniter");
    if (exists(root, "wp-config.php") || keys.some((k) => k.startsWith("wordpress/")))
      tags.push("wordpress");
    if (keys.some((k) => k.startsWith("drupal/"))) tags.push("drupal");
    if (keys.some((k) => k.startsWith("magento/"))) tags.push("magento");
    return tags;
  },

  // --- Python ---
  (root, cache) => {
    const pyproject = readSafe(root, "pyproject.toml", cache);
    const requirements = readSafe(root, "requirements.txt", cache);
    const setupPy = readSafe(root, "setup.py", cache);
    const tags: string[] = [];
    const haveAny =
      pyproject || requirements || setupPy || exists(root, "manage.py") || exists(root, "Pipfile");
    if (!haveAny) return [];
    tags.push("python");

    const haystack = [pyproject ?? "", requirements ?? "", setupPy ?? ""].join("\n").toLowerCase();
    const hasDep = (re: RegExp) => re.test(haystack);

    if (exists(root, "manage.py") || hasDep(/\bdjango\b/)) tags.push("django");
    if (hasDep(/\bdjangorestframework\b|\brest_framework\b/)) tags.push("djangorestframework");
    if (hasDep(/\bflask\b/)) tags.push("flask");
    if (hasDep(/\bfastapi\b/)) tags.push("fastapi");
    if (hasDep(/\bstarlette\b/)) tags.push("starlette");
    if (hasDep(/\baiohttp\b/)) tags.push("aiohttp");
    if (hasDep(/\btornado\b/)) tags.push("tornado");
    if (hasDep(/\bsanic\b/)) tags.push("sanic");
    if (hasDep(/\bbottle\b/)) tags.push("bottle");
    if (hasDep(/\bfalcon\b/)) tags.push("falcon");
    if (hasDep(/\bcelery\b/)) tags.push("celery");
    if (hasDep(/\bairflow\b|\bapache-airflow\b/)) tags.push("airflow");
    return tags;
  },

  // --- Ruby ---
  (root, cache) => {
    const gemfile = readSafe(root, "Gemfile", cache);
    if (!gemfile && !exists(root, "Gemfile.lock")) return [];
    const tags: string[] = ["ruby"];
    const lock = readSafe(root, "Gemfile.lock", cache);
    const haystack = `${gemfile ?? ""}\n${lock ?? ""}`.toLowerCase();
    if (
      /[\s'"]rails[\s'"]/.test(haystack) ||
      exists(root, "config/routes.rb") ||
      exists(root, "bin/rails")
    )
      tags.push("rails");
    if (/\bsinatra\b/.test(haystack)) tags.push("sinatra");
    if (/\bgrape\b/.test(haystack)) tags.push("grape");
    if (/\bhanami\b/.test(haystack)) tags.push("hanami");
    if (/\broda\b/.test(haystack)) tags.push("roda");
    return tags;
  },

  // --- Go ---
  (root, cache) => {
    const gomod = readSafe(root, "go.mod", cache);
    if (!gomod) return [];
    const tags: string[] = ["go"];
    const lower = gomod.toLowerCase();
    if (/github\.com\/gin-gonic\/gin\b/.test(lower)) tags.push("gin");
    if (/github\.com\/labstack\/echo\b/.test(lower)) tags.push("echo");
    if (/github\.com\/gofiber\/fiber\b/.test(lower)) tags.push("fiber");
    if (/github\.com\/go-chi\/chi\b/.test(lower)) tags.push("chi");
    if (/github\.com\/gorilla\/mux\b/.test(lower)) tags.push("gorilla");
    if (/github\.com\/gobuffalo\/buffalo\b/.test(lower)) tags.push("buffalo");
    if (/google\.golang\.org\/grpc\b/.test(lower)) tags.push("grpc");
    if (/connectrpc\.com\/connect\b/.test(lower)) tags.push("connectrpc");
    if (/github\.com\/spf13\/cobra\b/.test(lower)) tags.push("cobra");
    return tags;
  },

  // --- Rust ---
  (root, cache) => {
    const cargo = readSafe(root, "Cargo.toml", cache);
    if (!cargo) return [];
    const tags: string[] = ["rust"];
    const lower = cargo.toLowerCase();
    if (/\bactix-web\b/.test(lower)) tags.push("actix");
    if (/\baxum\b/.test(lower)) tags.push("axum");
    if (/\brocket\b/.test(lower)) tags.push("rocket");
    if (/\bwarp\b/.test(lower)) tags.push("warp");
    if (/\btide\b/.test(lower)) tags.push("tide");
    if (/\bpoem\b/.test(lower)) tags.push("poem");
    if (/\btonic\b/.test(lower)) tags.push("tonic");
    if (/\blambda_runtime\b/.test(lower)) tags.push("lambda-rs");
    return tags;
  },

  // --- JVM ---
  (root, cache) => {
    const pom = readSafe(root, "pom.xml", cache);
    const buildGradle = readSafe(root, "build.gradle", cache);
    const buildGradleKts = readSafe(root, "build.gradle.kts", cache);
    if (!pom && !buildGradle && !buildGradleKts) return [];
    const tags: string[] = ["jvm"];
    const haystack = `${pom ?? ""}\n${buildGradle ?? ""}\n${buildGradleKts ?? ""}`.toLowerCase();
    if (/\borg\.springframework\b|\bspring-boot\b/.test(haystack)) tags.push("spring");
    if (/\bktor\b/.test(haystack)) tags.push("ktor");
    if (/\bmicronaut\b/.test(haystack)) tags.push("micronaut");
    if (/\bjavax\.ws\.rs\b|\bjakarta\.ws\.rs\b/.test(haystack)) tags.push("jaxrs");
    return tags;
  },

  // --- .NET ---
  (root) => {
    const tags: string[] = [];
    const csprojs = listDir(root, ".").filter((f) => f.endsWith(".csproj"));
    if (csprojs.length === 0 && !exists(root, "global.json")) return tags;
    tags.push("dotnet");
    return tags;
  },

  // --- Elixir / Erlang ---
  (root, cache) => {
    const mix = readSafe(root, "mix.exs", cache);
    if (!mix) return [];
    const tags: string[] = ["elixir"];
    const lower = mix.toLowerCase();
    if (/:phoenix\b|"phoenix"|phoenix,/.test(lower)) tags.push("phoenix");
    return tags;
  },
  (root, cache) => {
    const rebar = readSafe(root, "rebar.config", cache);
    if (!rebar && !listDir(root, "src").some((f) => f.endsWith(".erl"))) return [];
    const tags: string[] = ["erlang"];
    const lower = (rebar ?? "").toLowerCase();
    if (/\bcowboy\b/.test(lower)) tags.push("cowboy");
    return tags;
  },

  // --- Crystal ---
  (root, cache) => {
    const shard = readSafe(root, "shard.yml", cache);
    if (!shard) return [];
    const tags: string[] = ["crystal"];
    if (/\bkemal\b/i.test(shard)) tags.push("kemal");
    return tags;
  },

  // --- Clojure ---
  (root, cache) => {
    const projectClj = readSafe(root, "project.clj", cache);
    const depsEdn = readSafe(root, "deps.edn", cache);
    if (!projectClj && !depsEdn) return [];
    const tags: string[] = ["clojure"];
    return tags;
  },

  // --- Swift / Vapor / iOS ---
  (root, cache) => {
    const pkg = readSafe(root, "Package.swift", cache);
    const hasXcode = listDir(root, ".").some(
      (f) => f.endsWith(".xcodeproj") || f.endsWith(".xcworkspace"),
    );
    const hasInfoPlist = exists(root, "Info.plist");
    if (!pkg && !hasXcode && !hasInfoPlist) return [];
    const tags: string[] = ["swift"];
    if (hasXcode || hasInfoPlist) tags.push("ios");
    if (pkg && /\bvapor\b/i.test(pkg)) tags.push("vapor");
    return tags;
  },

  // --- Dart ---
  (root, cache) => {
    const pubspec = readSafe(root, "pubspec.yaml", cache);
    if (!pubspec) return [];
    const tags: string[] = ["dart"];
    if (/^\s*flutter\s*:\s*$/m.test(pubspec) || /\bsdk:\s*flutter\b/.test(pubspec))
      tags.push("flutter");
    if (/\bshelf\s*:/i.test(pubspec) || /\bshelf_router\s*:/i.test(pubspec)) tags.push("shelf");
    return tags;
  },

  // --- Salesforce / Apex ---
  (root) => {
    if (exists(root, "sfdx-project.json") || exists(root, "force-app"))
      return ["apex", "salesforce"];
    return [];
  },

  // --- Android ---
  (root) => {
    const tags: string[] = [];
    if (
      exists(root, "AndroidManifest.xml") ||
      listDir(root, "app").includes("AndroidManifest.xml") ||
      listDir(root, "app/src/main").includes("AndroidManifest.xml")
    ) {
      tags.push("android");
    }
    return tags;
  },

  // --- Cloud function platforms ---
  (root, cache) => {
    const tags: string[] = [];
    // AWS Lambda — serverless.yml, SAM template, samconfig
    const serverless =
      readSafe(root, "serverless.yml", cache) ?? readSafe(root, "serverless.yaml", cache);
    const samTemplate =
      readSafe(root, "template.yaml", cache) ?? readSafe(root, "template.yml", cache);
    if (
      serverless ||
      (samTemplate && /AWS::Serverless::Function|aws::lambda::function/i.test(samTemplate)) ||
      exists(root, "samconfig.toml")
    ) {
      tags.push("aws-lambda");
    }
    return tags;
  },
  (root, cache) => {
    const tags: string[] = [];
    // GCP Cloud Functions — cloudbuild + functions framework dep
    if (exists(root, "cloudbuild.yaml") || exists(root, "cloudbuild.yml")) {
      tags.push("gcp-cloud-functions");
    }
    const pkg = readSafe(root, "package.json", cache);
    if (pkg && /@google-cloud\/functions-framework/.test(pkg)) tags.push("gcp-cloud-functions");
    const reqs = readSafe(root, "requirements.txt", cache);
    if (reqs && /\bfunctions-framework\b/.test(reqs)) tags.push("gcp-cloud-functions");
    // Dedupe (the GCP tag may already be present from package.json + cloudbuild)
    return Array.from(new Set(tags));
  },
  (root) => {
    // Azure Functions — host.json + function.json folders, or `.csproj` with
    // Microsoft.Azure.Functions reference.
    const hostJson = exists(root, "host.json");
    if (!hostJson) return [];
    return ["azure-functions"];
  },

  // --- Generic infra signals (don't gate matchers, but useful for prompt) ---
  (root) => {
    const tags: string[] = [];
    if (exists(root, "Dockerfile") || listDir(root, ".").some((f) => f === "Dockerfile"))
      tags.push("docker");
    if (exists(root, "terraform") || listDir(root, ".").some((f) => f.endsWith(".tf")))
      tags.push("terraform");
    if (exists(root, ".github/workflows")) tags.push("github-actions");
    return tags;
  },
];

/**
 * Walk the project root once, collect normalized tech tags. Pure / no
 * side effects; persistence is a separate function.
 */
export function detectTech(rootPath: string): DetectedTech {
  const absRoot = path.resolve(rootPath);
  const cache = new Map<string, string | null>();
  const tags = new Set<string>();
  const sentinels = new Set<string>();

  const COMMON_SENTINELS = [
    "package.json",
    "composer.json",
    "artisan",
    "pyproject.toml",
    "requirements.txt",
    "setup.py",
    "manage.py",
    "Pipfile",
    "Gemfile",
    "Gemfile.lock",
    "config/routes.rb",
    "bin/rails",
    "go.mod",
    "Cargo.toml",
    "pom.xml",
    "mix.exs",
    "rebar.config",
    "shard.yml",
    "project.clj",
    "deps.edn",
    "Package.swift",
    "Info.plist",
    "pubspec.yaml",
    "sfdx-project.json",
    "AndroidManifest.xml",
    "serverless.yml",
    "serverless.yaml",
    "template.yaml",
    "template.yml",
    "samconfig.toml",
    "host.json",
    "cloudbuild.yaml",
    "cloudbuild.yml",
    "build.gradle",
    "build.gradle.kts",
    "global.json",
    "Dockerfile",
    "wrangler.toml",
    "wrangler.jsonc",
    "deno.json",
    "deno.jsonc",
    "deno.lock",
    "bun.lockb",
    "bun.lock",
    "next.config.js",
    "next.config.ts",
    "next.config.mjs",
    "wp-config.php",
  ];
  for (const s of COMMON_SENTINELS) {
    if (exists(absRoot, s)) sentinels.add(s);
  }

  for (const det of detectors) {
    try {
      for (const t of det(absRoot, cache)) tags.add(t);
    } catch {
      // a single detector failure shouldn't kill detection
    }
  }

  return {
    tags: Array.from(tags).sort(),
    sentinels: Array.from(sentinels).sort(),
    detectedAt: new Date().toISOString(),
    rootPath: absRoot,
  };
}

/** Persist detection result to `data/<projectId>/tech.json`. */
export function writeTechJson(projectId: string, detected: DetectedTech): string {
  const out = path.join(dataDir(projectId), "tech.json");
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, JSON.stringify(detected, null, 2) + "\n");
  return out;
}

/**
 * Read the persisted tech.json for a project. Returns null when absent —
 * callers should treat that as "tech detection hasn't been run yet" rather
 * than "no tech detected" (those are very different signals).
 */
export function readTechJson(projectId: string): DetectedTech | null {
  const p = path.join(dataDir(projectId), "tech.json");
  if (!fs.existsSync(p)) return null;
  try {
    return JSON.parse(fs.readFileSync(p, "utf-8")) as DetectedTech;
  } catch {
    return null;
  }
}

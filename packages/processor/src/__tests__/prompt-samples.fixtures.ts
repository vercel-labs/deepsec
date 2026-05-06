import type { CandidateMatch, FileRecord } from "@deepsec/core";
import { TECH_HIGHLIGHTS } from "../prompt/highlights.js";

/**
 * Scenarios used to generate the deterministic samples in
 * `prompt-samples/` (committed to git). Each scenario maps to a single
 * file `<name>.md` containing the FULL prompt the model receives — the
 * assembled system-prompt half (core + tech highlights + slug notes +
 * INFO.md + promptAppend) AND the agent-layer wrapper that lists the
 * actual target files and the JSON output spec.
 *
 * Define realistic file records here; the generator derives
 * `batchLanguages` from extensions and `batchSlugs` from candidate
 * slugs. This keeps the scenarios honest — they exercise the same code
 * path the production processor takes.
 *
 * The test in `prompt-samples.test.ts` verifies the on-disk samples
 * match what the assembler + agent layer produce today. Set
 * `UPDATE_PROMPT_SAMPLES=1` when intentional changes shift output.
 */
interface PromptSampleScenario {
  /** Slug for the file name; numbered prefix keeps a stable directory order. */
  name: string;
  /** One-line description rendered as a comment in the sample header. */
  description: string;
  /** Project-level detected tech tags (from `detectTech()`). */
  detectedTags: string[];
  /** Synthetic batch — drives both `batchLanguages` and `batchSlugs`. */
  files: Array<{
    /** Repo-relative path; extension drives the language tag. */
    path: string;
    /** Candidates the scanner produced for this file. */
    candidates: Array<{ slug: string; lines: number[]; pattern: string }>;
  }>;
  /** Optional INFO.md content (already loaded by caller in production). */
  projectInfo?: string;
  /** Optional config.json:promptAppend content. */
  promptAppend?: string;
}

/**
 * Convert a scenario's `files` list into the FileRecord[] shape the
 * agent layer expects. Other FileRecord fields are filled with stable
 * placeholder values so the generated prompts stay deterministic.
 */
export function scenarioBatch(scenario: PromptSampleScenario): FileRecord[] {
  return scenario.files.map((f) => {
    const candidates: CandidateMatch[] = f.candidates.map((c) => ({
      vulnSlug: c.slug,
      lineNumbers: c.lines,
      snippet: "",
      matchedPattern: c.pattern,
    }));
    const record: FileRecord = {
      filePath: f.path,
      projectId: "sample",
      candidates,
      lastScannedAt: "1970-01-01T00:00:00.000Z",
      lastScannedRunId: "sample",
      fileHash: "",
      findings: [],
      analysisHistory: [],
      status: "pending",
    };
    return record;
  });
}

export const PROMPT_SAMPLE_SCENARIOS: PromptSampleScenario[] = [
  {
    name: "01-empty-project",
    description:
      "No tech detected; one file with no candidates. The assembler returns the bare core, then the agent layer adds Target Files + Investigation Instructions + Output Format.",
    detectedTags: [],
    files: [{ path: "src/index.ts", candidates: [] }],
  },
  {
    name: "02-nextjs-tsx-batch",
    description:
      "Typical Next.js + React project, batch of .tsx files. Carries Next.js + React highlights and slug notes for the matched candidates.",
    detectedTags: ["nextjs", "react", "node"],
    files: [
      {
        path: "app/dashboard/actions.ts",
        candidates: [
          {
            slug: "all-server-actions",
            lines: [12, 34],
            pattern: "Server Action export — investigate auth + ownership",
          },
        ],
      },
      {
        path: "app/profile/page.tsx",
        candidates: [
          {
            slug: "xss",
            lines: [48],
            pattern: "dangerouslySetInnerHTML",
          },
          {
            slug: "dangerous-html",
            lines: [62],
            pattern: "innerHTML assignment",
          },
        ],
      },
    ],
  },
  {
    name: "03-django-py-batch",
    description: "Django project, batch of .py files.",
    detectedTags: ["django", "python"],
    files: [
      {
        path: "app/views.py",
        candidates: [
          {
            slug: "py-django-view",
            lines: [22, 41],
            pattern: "function-based view (def view(request))",
          },
          {
            slug: "sql-injection",
            lines: [55],
            pattern: "Model.objects.raw with f-string",
          },
        ],
      },
      {
        path: "app/settings.py",
        candidates: [
          {
            slug: "secrets-exposure",
            lines: [8],
            pattern: "SECRET_KEY hardcoded",
          },
        ],
      },
    ],
  },
  {
    name: "04-polyglot-python-batch-filters-other-techs",
    description:
      "Polyglot repo (Next.js + Express + Django + Rails) but the batch is pure Python. The Next.js / Express / Rails highlights are filtered out by language; only Django remains.",
    detectedTags: ["nextjs", "react", "express", "django", "rails", "node"],
    files: [
      {
        path: "services/api/views.py",
        candidates: [
          {
            slug: "py-django-view",
            lines: [33],
            pattern: "class-based view",
          },
          {
            slug: "sql-injection",
            lines: [44],
            pattern: "cursor.execute with %-formatted SQL",
          },
        ],
      },
    ],
  },
  {
    name: "05-polyglot-typescript-batch-filters-other-techs",
    description:
      "Same polyglot repo as scenario 4, but the batch is pure TypeScript. Django and Rails highlights drop out; Next.js / React / Express remain.",
    detectedTags: ["nextjs", "react", "express", "django", "rails", "node"],
    files: [
      {
        path: "apps/web/app/api/login/route.ts",
        candidates: [
          {
            slug: "all-server-actions",
            lines: [9],
            pattern: "POST handler — auth check",
          },
        ],
      },
      {
        path: "apps/api/src/server.ts",
        candidates: [
          {
            slug: "js-express-route",
            lines: [12, 18, 24],
            pattern: "app/router method registration",
          },
          { slug: "xss", lines: [40], pattern: "innerHTML" },
        ],
      },
    ],
  },
  {
    name: "06-polyglot-mixed-batch",
    description:
      "Mixed-language batch (TypeScript + Python + Go) in a polyglot repo. Each language pulls in only its own highlights from the project-wide tag list.",
    detectedTags: ["nextjs", "react", "django", "gin", "node"],
    files: [
      {
        path: "apps/web/app/actions.ts",
        candidates: [
          {
            slug: "all-server-actions",
            lines: [7],
            pattern: "Server Action export",
          },
        ],
      },
      {
        path: "services/api/views.py",
        candidates: [
          {
            slug: "py-django-view",
            lines: [11],
            pattern: "class-based view",
          },
          {
            slug: "sql-injection",
            lines: [29],
            pattern: "f-string SQL",
          },
        ],
      },
      {
        path: "services/edge/main.go",
        candidates: [
          {
            slug: "go-gin-route",
            lines: [21],
            pattern: "Gin method registration",
          },
        ],
      },
    ],
  },
  {
    name: "07-overflow-fallback",
    description:
      "All known frameworks detected and a single file with no clear language tag — the framework section overruns the size budget and falls back to a single one-line summary.",
    detectedTags: TECH_HIGHLIGHTS.map((h) => h.tag),
    // No language tag → assembler treats it as "no batch filter" → all
    // detected tags are eligible, which trips the polyglot fallback.
    files: [{ path: "infra/Dockerfile", candidates: [] }],
  },
  {
    name: "08-with-info-and-append",
    description:
      "Next.js batch with a project INFO.md and a config.json:promptAppend addendum — shows their position in the assembled prompt and confirms they aren't double-emitted by the agent layer.",
    detectedTags: ["nextjs", "react"],
    files: [
      {
        path: "app/secrets.tsx",
        candidates: [
          { slug: "xss", lines: [22], pattern: "dangerouslySetInnerHTML" },
          {
            slug: "secret-in-fallback",
            lines: [4],
            pattern: 'process.env.X || "..."',
          },
        ],
      },
    ],
    projectInfo:
      "## Project notes\n\n- Auth helper is `requireUser()` from `lib/auth.ts`.\n- Internal-only routes live under `app/(internal)/**`.",
    promptAppend:
      "Custom: also flag any logger that swallows errors silently — that is a known foot-gun in this repo.",
  },
  {
    name: "09-laravel-php-batch",
    description: "Laravel project, batch of .php controller files.",
    detectedTags: ["laravel", "php"],
    files: [
      {
        path: "app/Http/Controllers/UsersController.php",
        candidates: [
          {
            slug: "php-laravel-route",
            lines: [14, 22],
            pattern: "Controller class",
          },
          {
            slug: "sql-injection",
            lines: [31],
            pattern: "DB::raw with interpolated input",
          },
          { slug: "xss", lines: [48], pattern: "Blade {!! !!} render" },
        ],
      },
    ],
  },
  {
    name: "10-rails-rb-batch",
    description:
      "Rails project, batch of .rb controller files. Confirms the Rails highlight names raw / html_safe / <%== %> as XSS sinks (NOT bare <%= %>, which auto-escapes in Rails 3+).",
    detectedTags: ["rails", "ruby"],
    files: [
      {
        path: "app/controllers/posts_controller.rb",
        candidates: [
          {
            slug: "rb-rails-controller",
            lines: [4, 18],
            pattern: "Rails controller class",
          },
          {
            slug: "sql-injection",
            lines: [29],
            pattern: "where(\"col = '#{x}'\")",
          },
          {
            slug: "open-redirect",
            lines: [44],
            pattern: "redirect_to params[:return_to]",
          },
        ],
      },
    ],
  },
  {
    name: "11-go-multi-framework-batch",
    description:
      "Go project that pulls in two Go frameworks (Gin + Chi) — both highlights ship for a Go-only batch.",
    detectedTags: ["gin", "chi", "go"],
    files: [
      {
        path: "cmd/server/main.go",
        candidates: [
          {
            slug: "go-gin-route",
            lines: [18],
            pattern: "Gin method registration",
          },
          {
            slug: "go-chi-route",
            lines: [42],
            pattern: "Chi method registration",
          },
          {
            slug: "go-ssrf",
            lines: [60],
            pattern: "http.Get with concatenated URL",
          },
        ],
      },
    ],
  },
];

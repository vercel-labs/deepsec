# Supported tech

Canonical list of frameworks and ecosystems deepsec recognizes out of the box.
Each entry tells you three things:

1. **How deepsec detects it** — which sentinel files / lockfile shapes
   trigger the tech tag. See `packages/scanner/src/detect-tech.ts`.
2. **What it scans for** — the matcher slugs that activate when the tech
   is detected. Matchers without a tech gate run on every repo.
3. **What the prompt knows about** — the per-tech "threat highlights"
   block that gets injected when the tech is detected. See
   `packages/processor/src/prompt/highlights.ts`.

Detection happens once per scan, with results persisted to
`data/<projectId>/tech.json`. Matcher gates and prompt highlights share
that single signal.

> **Plugin authors:** before adding a matcher for a framework already on
> this list, check whether you can extend the existing matcher instead.
> If your framework is missing, add a detector entry + matcher + prompt
> highlight together in one PR.

## TypeScript / JavaScript (Node, Bun, Deno, Workers)

### Next.js (`nextjs`)
- **Sentinel detection:** `package.json` depends on `next`; or
  `next.config.{js,ts,mjs}` is present.
- **Matchers:** `all-route-handlers`, `all-server-actions`,
  `nextjs-middleware`, `nextjs-middleware-only-auth`,
  `framework-server-action`, `framework-untrusted-fetch`,
  `framework-internal-header`, `framework-image-optimizer`,
  `framework-edge-sandbox`, `page-data-fetch`, `page-without-auth-fetch`,
  `use-server-export`, `unsafe-json-in-html`.
- **Prompt highlights:** middleware.ts is not sufficient auth, Server
  Actions are public POSTs, JSON-in-script XSS, search-param trust,
  cache-tag cross-tenant leaks.

### React (`react`)
- **Sentinel detection:** `react` or `react-dom` in `package.json`.
- **Matchers:** `dangerous-html`, `xss`, `postmessage-origin`.
- **Prompt highlights:** `dangerouslySetInnerHTML` with DB-stored HTML,
  ref/effect-driven open redirects, JSON-in-script escapes.

### Express (`express`)
- **Sentinel detection:** `express` in `package.json`.
- **Matchers:** `js-express-route` (gated), plus all generic JS matchers.
- **Prompt highlights:** route-vs-middleware ordering, `req.*` injection
  surfaces, `express.static` traversal, error-leak responses, CORS reflect.

### Fastify (`fastify`)
- **Sentinel detection:** `fastify` in `package.json`.
- **Matchers:** `js-fastify-route` (gated).
- **Prompt highlights:** `preHandler`/`onRequest` auth, schema validation
  as the FP mitigation, plugin scope inheritance.

### NestJS (`nestjs`)
- **Sentinel detection:** any `@nestjs/*` package in `package.json`.
- **Matchers:** `js-nestjs-controller` (gated).
- **Prompt highlights:** missing `@UseGuards`, untyped `@Body()`,
  `@Public()` opt-outs of global auth.

### Hono (`hono`)
- **Sentinel detection:** `hono` in `package.json`.
- **Matchers:** `js-hono-route` (gated).
- **Prompt highlights:** middleware-before-routes ordering, `c.req.*`
  trust, edge-runtime trust boundary to backend.

### Other JS detected (no dedicated matcher yet)
`koa`, `hapi`, `remix`, `sveltekit`, `nuxt`, `astro`, `solidstart`,
`trpc`, `mcp`, `connectrpc`, `graphql`, `socketio`, `bullmq`, `drizzle`,
`prisma`, `bun`, `deno`, `workers`. The generic JS/TS matchers
(`all-route-handlers`, `cors-wildcard`, `secret-env-var`, etc.) still run.

## Python

### Django / DRF (`django`, `djangorestframework`)
- **Sentinel detection:** `manage.py`, `Django` in
  `requirements.txt`/`pyproject.toml`/`setup.py`.
- **Matchers:** `py-django-view` (gated).
- **Prompt highlights:** `@csrf_exempt` on writes, raw SQL via
  f-strings, `mark_safe`, `ModelForm` mass assignment, DEBUG/ALLOWED_HOSTS
  leaks, DRF `permission_classes` gaps.

### FastAPI (`fastapi`)
- **Sentinel detection:** `fastapi` in deps.
- **Matchers:** `py-fastapi-route` (gated).
- **Prompt highlights:** missing `Depends(...)` auth, `Optional[Any]`
  escape hatches, missing `response_model`, `StaticFiles` traversal.

### Flask (`flask`)
- **Sentinel detection:** `flask` in deps.
- **Matchers:** `py-flask-route` (gated).
- **Prompt highlights:** `@login_required` decorator order, SSTI via
  `render_template_string`, raw SQL via `db.engine.execute(f"...")`,
  `send_from_directory` traversal, hardcoded `secret_key`.

### Other Python detected
`starlette`, `aiohttp`, `tornado`, `sanic`, `bottle`, `falcon`,
`celery`, `airflow`. Detection runs; dedicated matchers are roadmap.

## PHP

### Laravel (`laravel`)
- **Sentinel detection:** `composer.json` depends on `laravel/*`, or
  `artisan` script present.
- **Matchers:** `php-laravel-route` (gated).
- **Prompt highlights:** mass assignment via `$request->all()`,
  `DB::raw`/`whereRaw` SQL injection, `VerifyCsrfToken::$except` gaps,
  Blade `{!! !!}` XSS, routes outside the `auth` middleware group.

### Other PHP detected
`symfony`, `slim`, `yii`, `cakephp`, `codeigniter`, `wordpress`,
`drupal`, `magento`. Roadmap.

## Ruby

### Rails (`rails`)
- **Sentinel detection:** `Gemfile` mentions `rails`, or
  `config/routes.rb` / `bin/rails` exist.
- **Matchers:** `rb-rails-controller` (gated).
- **Prompt highlights:** `skip_before_action :authenticate_user!`,
  strong-params bypasses, `raw`/`html_safe` XSS, raw SQL, open redirect.

### Other Ruby detected
`sinatra`, `grape`, `hanami`, `roda`. Roadmap.

## Go

### Gin (`gin`)
- **Sentinel detection:** `go.mod` requires `github.com/gin-gonic/gin`.
- **Matchers:** `go-gin-route` (gated).
- **Prompt highlights:** route-vs-middleware ordering, `c.Query`/`c.Param`
  trust, template auto-escaping vs `safehtml`.

### Echo (`echo`)
- **Sentinel detection:** `go.mod` requires `github.com/labstack/echo`.
- **Matchers:** `go-echo-route` (gated).
- **Prompt highlights:** `e.Use` order, `c.Bind` allowlists, group-level
  middleware scope.

### Fiber (`fiber`)
- **Sentinel detection:** `go.mod` requires `github.com/gofiber/fiber`.
- **Matchers:** `go-fiber-route` (gated).
- **Prompt highlights:** middleware order, fasthttp body lifetime gotcha.

### Chi (`chi`)
- **Sentinel detection:** `go.mod` requires `github.com/go-chi/chi`.
- **Matchers:** `go-chi-route` (gated).
- **Prompt highlights:** `r.Mount` middleware inheritance gotcha,
  `chi.URLParam` trust, response-shape leakage.

### Generic Go (`go`)
Always-on Go matchers regardless of framework: `go-http-handler`,
`go-ssrf`, `go-command-injection`, `go-embed-asset`,
`connectrpc-handler-impl`, `proto-rpc-surface`, `unix-socket-listener`.

### Other Go detected
`gorilla`, `buffalo`, `grpc`, `connectrpc`, `cobra`. Roadmap for
dedicated matchers (gRPC service impl already partially covered).

## Rust

Detection emits tags (`actix`, `axum`, `rocket`, `warp`, `tide`, `poem`,
`tonic`, `lambda-rs`) but dedicated matchers are roadmap.

## JVM (Java / Kotlin)

Detection emits `jvm`, plus `spring`, `ktor`, `micronaut`, `jaxrs` when
present. Matchers are roadmap.

## .NET

Detection emits `dotnet` when a `.csproj` or `global.json` is present.
Matchers are roadmap.

## Cross-cutting infra (always-on)

Tags `docker`, `terraform`, `github-actions` are emitted but don't gate
matchers — the existing IaC and Dockerfile matchers (e.g.
`tf-iam-wildcard`, `dockerfile-from-mutable-tag`,
`github-workflow-security`) run unconditionally.

## Adding a new ecosystem

Three pieces, in one PR:

1. **Detector** — add a branch in `packages/scanner/src/detect-tech.ts`
   that emits the tag from a sentinel file or dependency.
2. **Matcher** — under `packages/scanner/src/matchers/<slug>.ts`, with
   `requires: { tech: ["<tag>"] }` so it only runs when detected. Register
   it in `packages/scanner/src/matchers/index.ts`.
3. **Prompt highlight** — add an entry to
   `packages/processor/src/prompt/highlights.ts` (3–6 short bullet lines).
   Don't write tutorials — the model knows the framework.

Tests:
- A `detect-tech.test.ts` case with a small fixture for the new tag.
- A matcher unit test in `framework-matchers.test.ts` (or sibling) with
  a known-vulnerable input that produces matches and a known-safe input
  that doesn't.
- The existing `prompt-assemble.test.ts` enforces a soft size cap on
  highlights — keep yours short.

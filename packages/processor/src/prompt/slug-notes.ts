/**
 * Per-slug one-line notes — pulled into the prompt only when the matched
 * slug appears in the current batch. Format: "what to check before
 * flagging." One sentence per slug. The matcher's `matchedPattern` already
 * tells the model what was matched; this adds the reviewer-instinct sentence.
 */

const SLUG_NOTES: Record<string, string> = {
  "all-route-handlers":
    "Coarse entry-point flag — confirm the handler reaches user input AND lacks auth/validation before flagging.",
  "all-server-actions":
    "Server Actions are public POST endpoints; flag any that don't explicitly check auth + ownership.",
  "nextjs-middleware-only-auth":
    "Next.js middleware.ts alone is NOT sufficient — confirm a backend framework guard wraps the handler too.",
  "framework-server-action":
    "Verify the action calls auth() / requireUser() before any DB write or external call.",
  "use-server-export":
    "Every `'use server'` export is publicly callable — auth must live IN the function, not just on the calling page.",
  "all-route-handlers-other": "Generic HTTP entry; trace input → sink before classifying.",
  "missing-auth":
    "Weak candidate — only flag if no auth wrapper, no role check, AND user-controlled input reaches a sink.",
  "auth-bypass":
    "Look for inverted booleans, early returns that skip checks, and `if (process.env.X) skipAuth()` patterns.",
  "cross-tenant-id":
    "User-supplied teamId/userId in DB queries — confirm the authenticated identity is used for the ownership check, not the request param alone.",
  "cors-wildcard":
    "`origin: true` + `credentials: true` is the high-severity shape; static `*` without credentials is usually fine.",
  "open-redirect":
    "Flag only if there's no allowlist, origin check, or hash-only redirect; relative paths starting with `//` are still external.",
  "unsafe-redirect":
    "Verify the redirect path passes through a validation function and that the validator can't be bypassed via encoding.",
  "dangerous-html":
    "DB-stored HTML is still untrusted — flag unless there's a sanitizer (DOMPurify, sanitize-html) BETWEEN the data and the render.",
  xss: "Check escape state at every step; raw concat into HTML, JSON-in-script without `</`-escape, and ref.innerHTML are the usual sinks.",
  rce: "Distinguish dynamic command (string concat → exec) from static command with sanitized args (which is fine).",
  "sql-injection":
    "Flag string-concat / template-literal SQL only if the variable is user-reachable; ORM `where({col: x})` is safe.",
  ssrf: "Check whether the URL host is constrained to an allowlist, blocked from RFC1918, or proxied via a vetted URL parser.",
  "path-traversal":
    "Flag if `path.join(root, userInput)` lacks a `path.resolve(...).startsWith(root)` containment check.",
  "secrets-exposure":
    "Distinguish real secrets from example values, dummy tokens in tests, and rotated/expired markers.",
  "secret-in-fallback":
    '`process.env.X || "hardcoded"` is the bug — only flag when the fallback looks like a real credential, not `"localhost"`.',
  "secret-in-log":
    "Logging full headers, request bodies, or error objects can leak Authorization tokens; flag if the log destination is durable.",
  "secret-env-var":
    "Direct env var reads in client-bundled code (NEXT_PUBLIC_*) are the bug — confirm the file isn't server-only.",
  "env-exposure":
    "Secrets reaching client bundles via `NEXT_PUBLIC_` / `VITE_` / build-time inlining — flag only if the env var holds a credential.",
  "rate-limit-bypass":
    "Sensitive operations (auth, password reset, expensive APIs) without rate-limit middleware are the high-signal cases.",
  "expensive-api-abuse":
    "LLM/AI/paid-API endpoints without per-user rate limits or auth — confirm the cost-per-call is non-trivial before flagging.",
  "webhook-handler":
    "Confirm signature verification (Stripe, GitHub, Shopify, Slack) happens BEFORE the body is parsed/processed.",
  "jwt-handling":
    "Look for `algorithm: 'none'`, missing `algorithms: ['HS256']` pinning, or skipping `verify()` in dev branches.",
  "iam-permissions":
    "Wildcards in Action AND Resource together are the dangerous shape; one or the other can be intentional.",
  "cache-key-poisoning":
    "Cache keys derived from request headers/cookies (User-Agent, Cookie, X-Forwarded-*) without normalization are the bug.",
  "public-endpoint":
    "Confirm the endpoint truly has no auth (not just a permissive guard) and that it returns sensitive data.",
  "service-entry-point":
    "Coarse flag — verify there's an actual auth gap, not just an internal-only handler reachable via service mesh.",
  "object-injection":
    "User-controlled keys into `obj[x] = v` without an allowlist enable prototype-pollution / overwriting safe defaults.",
  "spread-operator-injection":
    "Object spread precedence: later keys win. `{role: 'user', ...userInput}` is the bug — a trailing spread of attacker-controlled `userInput` can overwrite the earlier `role`. `{...userInput, role: 'user'}` is the safe order. Flag the trailing-spread shape.",
  "non-atomic-operation":
    "Read-then-write patterns without a lock / transaction / atomic op are TOCTOU; flag only if the resource is shared across requests.",
  "debug-endpoint":
    "Routes guarded by `process.env.NODE_ENV === 'development'` can ship to prod via env misconfig — flag if the route does anything sensitive.",
  "test-header-bypass":
    "`x-test-*` / `x-bypass-*` headers honored in handler code are the classic prod-leakage bug.",
  "dev-auth-bypass":
    "`if (env === 'dev') return adminUser` patterns — verify the env check can't be tricked, and that the path isn't reachable in prod.",
  "lua-ngx-exec":
    "`ngx.exec` / `ngx.redirect` / `os.execute` with concatenated request data is RCE-shaped on Lua/OpenResty.",
  "lua-shared-dict-poisoning":
    "Writes to `ngx.shared` from request data persist across requests — flag if the read path trusts the cached value.",
  "go-ssrf":
    "Concatenated URL passed to `http.Get` / `client.Do` without an allowlist — internal hosts are the high-severity case.",
  "go-command-injection":
    '`exec.Command("sh", "-c", interpolated)` is the bug; `exec.Command("cmd", arg1, arg2)` with discrete args is generally safe.',

  // --- Framework entry-point matchers (gated on detectTech) ---
  // These are coarse "this file is a public surface" flags. The matched
  // pattern alone is not a vulnerability — confirm an actual input → sink
  // path AND missing auth/validation before reporting.
  "js-express-route":
    "Weak entry-point candidate — confirm the handler reads `req.*` data AND lacks an auth wrapper / validator before flagging.",
  "js-fastify-route":
    "Weak entry-point candidate — confirm no `preHandler`/`onRequest` auth hook AND no schema validation before flagging.",
  "js-nestjs-controller":
    "Weak entry-point candidate — confirm no `@UseGuards` and no class-validator DTO before flagging.",
  "js-hono-route":
    "Weak entry-point candidate — confirm no auth `app.use(...)` precedes the route registration before flagging.",
  "py-django-view":
    "Weak entry-point candidate — confirm no `LoginRequiredMixin` / `@login_required` / DRF `permission_classes` AND that user input reaches a sink before flagging.",
  "py-fastapi-route":
    "Weak entry-point candidate — confirm no `Depends(auth)` / `Security(...)` and that input reaches a sink before flagging.",
  "py-flask-route":
    "Weak entry-point candidate — confirm no `@login_required` / `before_request` auth hook before flagging.",
  "rb-rails-controller":
    "Weak entry-point candidate — confirm `skip_before_action :authenticate_user!` is intentional or that no auth callback is in scope.",
  "php-laravel-route":
    "Weak entry-point candidate — confirm the route is outside the `auth` middleware group AND user input reaches a sink before flagging.",
  "go-gin-route":
    "Weak entry-point candidate — confirm no auth `r.Use(...)` precedes the route registration in this group.",
  "go-echo-route":
    'Weak entry-point candidate — confirm `e.Use(...)` auth precedes the route, and the route isn\'t on the bare engine when only `g := e.Group("/api", auth)` is guarded.',
  "go-fiber-route":
    "Weak entry-point candidate — confirm `app.Use(auth)` precedes the route and that no route-level middleware overrides the group middleware silently.",
  "go-chi-route":
    "Weak entry-point candidate — confirm `r.Use(auth)` is in scope and no `r.Mount(...)` later short-circuits the inheritance.",
  "js-koa-route":
    "Weak entry-point candidate — confirm auth middleware is registered BEFORE the route via `app.use(auth)`.",
  "js-hapi-route":
    "Weak entry-point candidate — confirm `auth: false` isn't set and that a default strategy was registered.",
  "js-remix-route":
    "Weak entry-point candidate — `loader`/`action` exports are public; verify `requireUserId(request)` (or equivalent) runs first.",
  "js-sveltekit-route":
    "Weak entry-point candidate — `+server.ts` and form `actions` are public; confirm `hooks.server.ts` enforces auth and isn't bypassed.",
  "js-nuxt-route":
    "Weak entry-point candidate — `defineEventHandler` files in `server/api` are public; confirm auth runs in handler or `server/middleware`.",
  "js-astro-endpoint":
    "Weak entry-point candidate — `pages/api/*` exports are public; SSR pages with `prerender = false` need handler-level auth.",
  "js-solidstart-action":
    "Weak entry-point candidate — `'use server'` exports are publicly callable; auth must live IN the function.",
  "js-graphql-resolver":
    "Per-resolver auth needed — confirm `context.user` (or schema directive) gates the field; no global auth applies.",
  "js-socketio-handler":
    "Weak entry-point candidate — confirm `io.use(auth)` runs before any `socket.on('event', ...)` handler executes.",
  "js-bullmq-processor":
    "`job.data` is producer-supplied — re-validate trust boundary at the queue if any web handler can enqueue.",
  "js-bun-serve":
    "Raw HTTP entry — no framework gates, all auth/validation lives in the `fetch` handler.",
  "js-deno-route":
    "Weak entry-point candidate — Deno has no built-in auth; middleware order is hand-rolled.",
  "js-workers-fetch":
    "Worker default-export `fetch` is the only entry — auth lives entirely in the handler; review `env.<BINDING>` permissions.",

  "php-symfony-controller":
    "Weak entry-point candidate — confirm `#[IsGranted]` / `security.yaml` access_control covers this route.",
  "php-slim-route":
    "Weak entry-point candidate — middleware via `->add(...)` is reverse-order; confirm auth attaches to the right group.",
  "php-yii-controller":
    "Weak entry-point candidate — every public `actionXxx()` is reachable; confirm `behaviors()` wires AccessControl.",
  "php-cakephp-controller":
    "Weak entry-point candidate — `$this->Auth->allow(...)` lists public actions; confirm scope.",
  "php-codeigniter-controller":
    "Weak entry-point candidate — confirm a Filter in `app/Config/Filters.php` covers this route.",
  "php-wordpress-rest":
    "Weak entry-point candidate — flag `permission_callback => __return_true` and `wp_ajax_nopriv_*` on sensitive operations.",
  "php-drupal-controller":
    "Weak entry-point candidate — `*.routing.yml` `_permission` of `access content` is permissive; confirm scope.",
  "php-magento-controller":
    "Weak entry-point candidate — confirm webapi.xml resource is not `anonymous` for sensitive actions.",

  "py-starlette-route":
    "Weak entry-point candidate — confirm AuthenticationMiddleware is wired and applies to this Mount.",
  "py-aiohttp-route":
    "Weak entry-point candidate — confirm an `@web.middleware` auth check is registered before the route.",
  "py-tornado-handler":
    "Weak entry-point candidate — confirm `@tornado.web.authenticated` is on each method handler.",
  "py-sanic-route":
    "Weak entry-point candidate — confirm `@app.middleware('request')` auth check applies to this blueprint.",
  "py-bottle-route":
    "Weak entry-point candidate — Bottle has no built-in auth; flag handlers with no decorator chain enforcing it.",
  "py-falcon-resource":
    "Weak entry-point candidate — confirm a middleware/hook sets `req.context.user` BEFORE the on_<method> runs.",
  "py-celery-task":
    "Background-job surface — confirm queue producer authenticates the user; pickle serializer = unsafe deserialization.",
  "py-airflow-dag":
    "Privileged scheduler surface — flag interpolated template fields (`{{ params.x }}`) reaching Bash/SQL/HTTP operators.",

  "rb-sinatra-route":
    "Weak entry-point candidate — confirm a `before do ... end` filter enforces auth on this route.",
  "rb-grape-endpoint":
    "Weak entry-point candidate — confirm a `before do ... end` or `helpers do ... end` block enforces auth.",
  "rb-hanami-action":
    "Weak entry-point candidate — confirm a `before` callback or middleware enforces auth on this Action class.",
  "rb-roda-route":
    "Weak entry-point candidate — auth must wrap the tree node, not just the leaf; confirm scope.",

  "go-gorilla-route":
    "Weak entry-point candidate — confirm `router.Use(auth)` covers this subrouter; `PathPrefix(...).Handler(other)` doesn't inherit.",
  "go-buffalo-route":
    "Weak entry-point candidate — confirm `app.Use(auth)` is registered before this route or resource.",
  "go-cobra-command":
    "Privileged CLI — flag interpolated user args reaching shell/SQL and any logging of `cmd.Flags()`.",

  "rs-actix-route":
    "Weak entry-point candidate — confirm `App::new().wrap(auth)` covers this scope and extractors validate content (not just structure).",
  "rs-axum-route":
    "Weak entry-point candidate — confirm `.layer(auth_layer)` precedes the route; check `.merge` / `.nest` order.",
  "rs-rocket-route":
    "Weak entry-point candidate — confirm a request guard (`fn from_request`) runs before this handler.",
  "rs-warp-filter":
    "Weak entry-point candidate — auth filter must precede the body extractor in the `.and()` chain.",
  "rs-tide-route":
    "Weak entry-point candidate — confirm `app.with(auth_middleware)` was registered before this route.",
  "rs-poem-route":
    "Weak entry-point candidate — confirm `.with(auth)` or `.around(auth)` wraps this endpoint.",
  "rs-tonic-grpc":
    "Per-method gRPC auth — confirm an Interceptor checks every method, not just selected ones.",
  "rs-lambda-runtime":
    "Lambda handler — confirm `event.payload.request_context.authorizer` claims are read; cold-start global state can leak across tenants.",

  "jvm-spring-controller":
    "Weak entry-point candidate — confirm `SecurityFilterChain` / `@PreAuthorize` covers this method; `permitAll()` is the bug.",
  "jvm-ktor-route":
    "Weak entry-point candidate — confirm this route is inside an `authenticate(...) { ... }` block.",
  "jvm-micronaut-controller":
    "Weak entry-point candidate — confirm `@Secured(...)` covers this method; `@PermitAll` opens it.",
  "jvm-jaxrs-resource":
    "Weak entry-point candidate — confirm `@RolesAllowed(...)` is set; absence on a `@Path` resource is public.",

  "dotnet-aspnet-controller":
    "Weak entry-point candidate — confirm `[Authorize]` covers the action; `[AllowAnonymous]` opens it back up.",
  "dotnet-minimal-api":
    "Weak entry-point candidate — confirm `.RequireAuthorization()` is chained on this map; `app.MapGet(...)` alone is public.",
  "dotnet-razor-pages":
    "Weak entry-point candidate — confirm `[Authorize]` on the page model and `[ValidateAntiForgeryToken]` on POST handlers.",
  "dotnet-azure-function":
    "Weak entry-point candidate — `AuthorizationLevel.Anonymous` is public; function/admin keys ≠ user identity.",

  "ex-phoenix-controller":
    "Weak entry-point candidate — confirm this route's `scope` uses an auth-bearing pipeline (e.g. `pipe_through [:api, :authenticated]`).",
  "cr-kemal-route":
    "Weak entry-point candidate — Kemal has no built-in auth; confirm a `before_*` filter intercepts.",
  "clj-ring-handler":
    "Weak entry-point candidate — confirm a `wrap-*` middleware (auth, anti-forgery) is in the chain before this handler.",
  "erl-cowboy-handler":
    "Weak entry-point candidate — auth check must happen in `init/2` before any state-changing call.",
  "swift-vapor-route":
    "Weak entry-point candidate — confirm this route is inside a `.grouped(guardMiddleware())` scope.",
  "dart-shelf-handler":
    "Weak entry-point candidate — Shelf has no built-in auth; confirm `Pipeline().addMiddleware(...)` registration order covers this route.",
  "apex-rest-resource":
    "`without sharing` BYPASSES row-level security — confirm intentional and that the resource can't be invoked by unprivileged users.",
  "lambda-aws-handler":
    "Lambda handler — confirm `event.requestContext.authorizer` is read; over-permissioned IAM role widens RCE blast radius.",
  "gcp-cloud-function":
    "Cloud Function — confirm not deployed with `--allow-unauthenticated`; integrate Identity Platform / Firebase Auth for user identity.",
  "azure-function-handler":
    "Azure Function — `AuthorizationLevel.Anonymous` is public; queue/blob triggers still receive user-influenced payloads.",
  "android-manifest-export":
    "Exported component — confirm `android:permission=` guards the IPC surface; pre-API-31 implicit intent-filters are exported by default.",
  "ios-url-scheme":
    "URL handler entry — `application(_:open:)` and `scene(_:openURLContexts:)` receive attacker-controlled URLs; review universal-link host association.",

  // --- Raw SQL escape hatches across language ecosystems ---
  // Each note covers the relevant driver-specific FP mitigations the
  // model should check before flagging.
  "js-sql-raw":
    "Raw-SQL across pg/mysql2/TypeORM/Sequelize/Knex/Kysely/postgres.js — flag string concat or template interpolation into SELECT/INSERT/UPDATE/DELETE; parameterized forms (`$1`, `:name`, prepared statements with separate args) are the safe shape. `sql\\`...\\`` tagged templates from libraries that escape (drizzle, postgres.js without `.unsafe`) are safe.",
  "js-nosql-injection":
    "MongoDB / Mongoose — `$where` with concat/function/template lets attackers run arbitrary JS in the DB. `find(JSON.parse(req.body...))` accepts attacker operator keys (`$ne`, `$gt`) — coerce to typed query first. `new RegExp(req.*)` is ReDoS-shaped.",
  "py-sql-raw":
    'Raw-SQL across SQLAlchemy/psycopg/pymysql/sqlite3/asyncpg/Django ORM — f-string, `%` formatting, `.format()`, and `+` concat into SQL are injection. The safe shape is `cursor.execute("... %s ...", (val,))` (psycopg) or `text("... :x ...").bindparams(x=val)` (SQLAlchemy).',
  "py-nosql-injection":
    'PyMongo — `$where: f"..."` runs JS in MongoDB. `coll.find({"$regex": request.args.get(...)})` is ReDoS / injection. Use typed query keys, validate operators server-side.',
  "jvm-sql-raw":
    "JDBC/JPA/Hibernate/JdbcTemplate/MyBatis/jOOQ/Exposed raw SQL — string concat into `executeQuery`/`createQuery`/`createNativeQuery` is injection even on PreparedStatement (concat happens before binding). MyBatis `${param}` is unsafe; `#{param}` parameterizes.",
  "php-sql-raw":
    'PDO/mysqli/Doctrine raw SQL — concat (`.`) into `query`/`exec`/`executeQuery` is SQL injection. PDO `prepare("... ? ...")` + `execute([val])` and Doctrine `executeQuery("... :x ...", [\'x\' => val])` are the safe forms.',
  "rb-sql-raw":
    'ActiveRecord/Sequel/pg-gem raw SQL — `#{}` interpolation in `find_by_sql`/`where("...")`/`Sequel.lit` is injection. `where(col: val)` (AR) and `where(Sequel[:col] => val)` (Sequel) are parameterized.',
  "go-sql-raw":
    'database/sql, GORM, sqlx, pgx — `fmt.Sprintf` or `+` concat into `Query`/`Exec`/`Raw` is SQL injection. `db.Query("... $1 ...", val)` (pgx/database/sql) and `db.Where("col = ?", val)` (GORM) are the safe shapes.',
  "rs-sql-raw":
    'Rust runtime SQL via `sqlx::query(&format!(...))` / `diesel::sql_query(format!(...))` / `Statement::from_string(format!(...))` is injection. Note: the COMPILE-TIME-checked `sqlx::query!("... {}", arg)` macro form is parameterized and SAFE — don\'t flag those.',
  "dotnet-sql-raw":
    'ADO.NET/Dapper/EF Core raw SQL — concat or `$"..."` interpolation into `SqlCommand`/`Query`/`Execute`/`FromSqlRaw` is injection. EF Core `FromSqlInterpolated($"... {x} ...")` parameterizes correctly; only `FromSqlRaw` with concat or `$"..."` is the bug.',
};

export function noteForSlug(slug: string): string | undefined {
  return SLUG_NOTES[slug];
}

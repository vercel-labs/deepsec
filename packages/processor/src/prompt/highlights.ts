/**
 * Per-tech threat highlights. Each entry is a terse bullet list naming the
 * high-signal threats and FP mitigations worth checking on a project that
 * uses this tech. The model already knows what these frameworks ARE — we
 * are pointing at threats the scanner can't see, not writing tutorials.
 *
 * Hard rule: 3–6 bullet lines, ~80–200 tokens. CI snapshot tests assert
 * size; reviewers should push back on tutorial-style additions.
 */

export interface TechHighlight {
  /** Tag from `detectTech()` this highlight applies to. */
  tag: string;
  /** Human-readable name used in the prompt header. */
  title: string;
  /**
   * Languages this highlight is relevant to. Used by the assembler to
   * scope a batch's highlights to the files actually in the batch — a
   * batch of Python files in a polyglot Next.js+Django repo doesn't
   * need Next.js highlights, even though the project as a whole has
   * them. Use the canonical language names from
   * `LANGUAGE_EXTENSIONS` in `@deepsec/scanner`: `typescript`,
   * `javascript`, `python`, `php`, `ruby`, `go`, `rust`, `java`,
   * `kotlin`, `csharp`, `lua`, `terraform`. Multiple languages allowed
   * (e.g. JS frameworks tag both `typescript` and `javascript`).
   */
  languages: string[];
  /** Bullet list — short lines, no prose. */
  bullets: string[];
}

/** Languages most JS/TS frameworks apply to — all four extension flavors. */
const JS_LANGS = ["typescript", "javascript"];

export const TECH_HIGHLIGHTS: TechHighlight[] = [
  // --- Node / TS / JS frameworks ---
  {
    tag: "nextjs",
    title: "Next.js",
    languages: JS_LANGS,
    bullets: [
      "Next.js `middleware.ts` runs at the edge and is NOT sufficient auth — too easy to misconfigure or bypass via routes that escape the matcher",
      "Server Actions are publicly callable POST endpoints — every one needs explicit auth + authorization checks",
      "`JSON.stringify()` inside `dangerouslySetInnerHTML` or inline `<script>` tags is XSS unless the output escapes `</` (look for `safeJsonStringify` or `\\u003c`)",
      "`searchParams` and dynamic route segments (`[id]`, `[...slug]`) are user-controlled — treat them as untrusted in middleware too",
      "`unstable_cache` / `revalidateTag` on user-supplied keys can leak across tenants",
    ],
  },
  {
    tag: "react",
    title: "React",
    languages: JS_LANGS,
    bullets: [
      "`dangerouslySetInnerHTML` with any user-influenceable string is XSS — DB values and usernames count as user-controlled",
      "Refs and effects that touch `document.location` / `window.opener` can become open-redirect or tabnabbing sinks",
      "Server-rendered JSON in `<script>` tags must escape `</` to be XSS-safe",
    ],
  },
  {
    tag: "express",
    title: "Express.js",
    languages: JS_LANGS,
    bullets: [
      "Each `app.get/post/...` and `router.use` is a public endpoint — confirm auth middleware actually wraps it (order matters; routes mounted before `app.use(authMiddleware)` are unprotected)",
      "`req.query`/`req.params`/`req.body` are user input; concatenation into SQL, shell, paths, or URLs is the usual sink",
      "`express.static` on a user-influenced root, or `res.sendFile(req.params.x)`, is path traversal",
      "Error handlers that send `err.stack` or `err.message` to the response leak internals",
      "CORS `origin: true` reflecting credentials enables CSRF-via-fetch",
    ],
  },
  {
    tag: "fastify",
    title: "Fastify",
    languages: JS_LANGS,
    bullets: [
      "`preHandler` / `onRequest` hooks are the auth layer; routes registered without them or before the auth plugin are unprotected",
      "Schema validation (`schema: { body, querystring }`) is the default mitigation — flag handlers that read raw `request.body` without a schema",
      "Plugins registered with `register()` inherit hooks per-scope; cross-scope auth bypass is common in monorepos",
      "`reply.send(err)` returns full error objects in dev mode; check the prod config",
    ],
  },
  {
    tag: "nestjs",
    title: "NestJS",
    languages: JS_LANGS,
    bullets: [
      "`@UseGuards(...)` on controller or method is the auth check; missing guards on a `@Controller()` are a common gap",
      "`@Body()` / `@Query()` without a `class-validator` DTO is unvalidated input",
      "Global pipes/interceptors registered late or only in main.ts may not apply to e2e-test routes shipped to prod",
      "`@Public()` decorators that opt OUT of a global auth guard — confirm they are intentional",
    ],
  },
  {
    tag: "hono",
    title: "Hono",
    languages: JS_LANGS,
    bullets: [
      "Each `app.get('/path', handler)` is a public endpoint; auth middleware (`app.use('*', auth)`) must come BEFORE the route declarations or it's a no-op",
      "`c.req.query()` / `c.req.param()` / `c.req.json()` are user input — usual injection surfaces apply",
      "Hono runs on Workers/edge runtimes — check whether route handlers reach into a separate Node backend without re-authenticating",
    ],
  },

  // --- Python ---
  {
    tag: "django",
    title: "Django",
    languages: ["python"],
    bullets: [
      "`@csrf_exempt` views handling state-changing POSTs without an alternate auth (signature, token) are CSRF-vulnerable",
      "`Model.objects.raw(...)` / `cursor.execute()` with f-string interpolation is SQL injection — flag any %-formatted SQL",
      "`mark_safe()` / `format_html()` on user input is XSS; same for `{% autoescape off %}` blocks",
      "`ModelForm` without `fields = [...]` (or with `__all__`) exposes mass-assignment of every model column",
      "`DEBUG=True` + `ALLOWED_HOSTS=['*']` in any reachable settings file leaks tracebacks and SECRET_KEY material",
    ],
  },
  {
    tag: "djangorestframework",
    title: "Django REST Framework",
    languages: ["python"],
    bullets: [
      "`permission_classes` missing or set to `AllowAny` on a sensitive `ModelViewSet` exposes full CRUD",
      "`ModelSerializer` with `fields = '__all__'` allows mass-assignment of admin-only columns via PATCH",
      "`@action(detail=True)` methods inherit the viewset's permissions but custom routers can break this — confirm",
    ],
  },
  {
    tag: "fastapi",
    title: "FastAPI",
    languages: ["python"],
    bullets: [
      "Auth lives in `Depends(...)`; routes without an auth dependency are public — `@app.get('/admin')` with no Depends is the common gap",
      "Pydantic models validate input but `Optional[Any]` / `dict` fields are an escape hatch — flag them on inputs",
      "`response_model=...` filters server output; without it, you may return DB columns containing secrets",
      "`StaticFiles(directory=...)` rooted at a user-influenced path is path traversal",
    ],
  },
  {
    tag: "flask",
    title: "Flask",
    languages: ["python"],
    bullets: [
      "`@app.route(...)` without a `@login_required` (or equivalent) decorator is public; check the order of decorators — `@app.route` must be outermost",
      "`render_template_string(user_input)` is server-side template injection (RCE)",
      '`request.args` / `request.form` / `request.json` interpolated into SQL via `db.engine.execute(f"...")` is SQL injection',
      "`send_from_directory(dir, request.args['file'])` without a basename check is path traversal",
      "`session` cookies use `app.secret_key` — hardcoded keys in source are session forgery",
    ],
  },

  // --- PHP ---
  {
    tag: "laravel",
    title: "Laravel",
    languages: ["php"],
    bullets: [
      "`Model::create($request->all())` without `$fillable`/`$guarded` is mass assignment — admin columns get overwritten",
      "`DB::raw()` / `whereRaw()` / `selectRaw()` with interpolated input is SQL injection",
      "`VerifyCsrfToken::$except` lists that include state-changing routes are CSRF-vulnerable unless an alternate verification (signed URL, webhook signature) exists",
      "Blade `{!! $x !!}` renders raw HTML — XSS sink",
      "Routes outside the `auth` middleware group, or routes with `->withoutMiddleware([...])`, need explicit per-action auth checks",
    ],
  },

  // --- Ruby ---
  {
    tag: "rails",
    title: "Ruby on Rails",
    languages: ["ruby"],
    bullets: [
      "`skip_before_action :authenticate_user!` on a controller (or specific action) — confirm it's intentional and not on a write endpoint",
      "Strong parameters: `params.require(:x).permit(...)` is the mass-assignment guard; `params[:x]` directly into `Model.update(...)` is the bug",
      "`raw(x)` / `x.html_safe` / `<%== %>` on user input is XSS — note that bare `<%= %>` auto-escapes in Rails ≥ 3 and is safe; flag the explicit unescape forms, not standard ERB output",
      "`find_by_sql` / `where(\"col = '#{x}'\")` is SQL injection — `where(col: x)` is the safe form",
      "`redirect_to params[:return_to]` is an open redirect; check for an allowlist",
    ],
  },

  // --- Go frameworks ---
  {
    tag: "gin",
    title: "Gin",
    languages: ["go"],
    bullets: [
      "Each `r.GET/POST/...` and `r.Group(...)` is a public endpoint; auth middleware applied via `r.Use(...)` must precede route registration in the same group",
      "`c.Query`/`c.Param`/`c.PostForm` are user input — usual injection surfaces (SQL, exec, fs, URL) apply",
      '`c.HTML(http.StatusOK, "tmpl", data)` with `data` containing untrusted strings is XSS unless the template uses `{{.X}}` (auto-escaped) and not `{{.X | safehtml}}`',
    ],
  },
  {
    tag: "echo",
    title: "Echo",
    languages: ["go"],
    bullets: [
      "`e.Use(middleware)` order matters — routes registered before `Use` aren't covered",
      '`c.Bind(&v)` accepts JSON/form/query — fields with `json:"-"` matter only if you USE `json:"-"`; explicit allowlists in DTO structs are the safe form',
      'Group-level middleware (`g := e.Group("/api", auth)`) — confirm sensitive routes live under the group, not on the root `e`',
    ],
  },
  {
    tag: "fiber",
    title: "Fiber",
    languages: ["go"],
    bullets: [
      "`app.Get/Post/...` registers public endpoints; middleware via `app.Use(auth)` must precede them, and route-level middleware override group middleware",
      "`c.Query` / `c.Params` / `c.Body` / `c.BodyParser(&v)` are user input; injection sinks are the same as net/http",
      "Fiber wraps fasthttp — request bodies/headers are not safe to retain past the handler return; flag goroutines that capture `c` by reference",
    ],
  },
  {
    tag: "chi",
    title: "Chi",
    languages: ["go"],
    bullets: [
      '`r.Use(middleware)` and `r.Group(...)` define auth scopes — sub-routers inherit, but `r.Mount("/x", h)` does NOT inherit middleware applied after the mount',
      '`chi.URLParam(r, "id")` is user input; treat as untrusted in DB / fs / exec calls',
      "`render.JSON(w, r, data)` returns whatever you pass — DB rows often include secret columns; use a response-shape struct",
    ],
  },
  {
    tag: "koa",
    title: "Koa",
    languages: JS_LANGS,
    bullets: [
      "`router.<verb>` routes registered before `app.use(authMiddleware)` are unprotected — middleware order matters",
      "`ctx.request.body` / `ctx.query` / `ctx.params` are user input; same injection sinks as Express",
      "`ctx.throw(401)` is a soft response — confirm it's reached BEFORE any data is fetched/returned",
      "`koa-bodyparser` defaults to forms+json; large payload limits and prototype-pollution opts must be set explicitly",
    ],
  },
  {
    tag: "hapi",
    title: "Hapi",
    languages: JS_LANGS,
    bullets: [
      "`auth: false` on a `server.route(...)` opts out of the default auth strategy — confirm it's intentional, especially on writes",
      "Validate routes use `validate: { query, payload, params }`; routes without validation pass raw input to handlers",
      "`server.auth.default(...)` sets the global gate; flag handlers that pre-date it or that pass `auth: 'optional'`",
      "`request.payload` / `request.query` / `request.params` are user input",
    ],
  },
  {
    tag: "remix",
    title: "Remix",
    languages: JS_LANGS,
    bullets: [
      "`action` functions are publicly callable POST endpoints — every one needs explicit auth (`requireUserId(request)` or equivalent)",
      "`loader` functions can return PII; avoid passing raw DB rows — shape the response",
      "Resource routes (no default export) accept any HTTP method by default — explicit method handlers are safer",
      "`redirect()` to user-controlled paths — confirm validation/allowlist before flagging",
    ],
  },
  {
    tag: "sveltekit",
    title: "SvelteKit",
    languages: JS_LANGS,
    bullets: [
      "`+server.ts` exports (`GET`/`POST`/...) are public — auth must live IN the handler, not just the page",
      "Form `actions` are server-callable from any client — confirm auth and CSRF (SvelteKit has built-in CSRF but check overrides)",
      "`load` functions in `+page.server.ts` run server-side and can leak via the streamed `data` prop — shape the return",
      "`hooks.server.ts` is the right place for global auth; flag routes that bypass it",
    ],
  },
  {
    tag: "nuxt",
    title: "Nuxt",
    languages: JS_LANGS,
    bullets: [
      "`server/api/**/*.ts` files become public endpoints — `defineEventHandler(async (event) => ...)` needs explicit auth",
      "`getQuery(event)` / `readBody(event)` / `getRouterParam(event)` are user input",
      "Server middleware in `server/middleware/` runs on EVERY request including `/_nuxt/*` — check for ordering",
      "`useRuntimeConfig().public.*` keys leak to the client bundle; only top-level `runtimeConfig.<key>` stays server-only",
    ],
  },
  {
    tag: "astro",
    title: "Astro",
    languages: JS_LANGS,
    bullets: [
      "`pages/api/**/*.ts` exports (`GET`/`POST`/...) are public; `prerender = false` opts a page into SSR with the same auth concerns",
      "`Astro.request` / `Astro.cookies` / `Astro.params` are user input — same sinks as Next.js",
      "Default output is static; double-check if a route silently became SSR via `export const prerender = false`",
      "Astro uses Vite — env vars prefixed with `PUBLIC_` ship to the client bundle",
    ],
  },
  {
    tag: "solidstart",
    title: "SolidStart",
    languages: JS_LANGS,
    bullets: [
      "`'use server'` exports and `action()` / `cache()` factories are publicly callable — auth must live INSIDE the function",
      "Server functions run with the request context but lack a built-in CSRF token; verify the deploy uses SameSite cookies",
      "`createAsync(() => fetch...)` data fetched server-side can include PII — shape the return",
    ],
  },
  {
    tag: "graphql",
    title: "GraphQL",
    languages: JS_LANGS,
    bullets: [
      "Per-resolver auth: every Query/Mutation/Subscription field is independently reachable — flag resolvers that don't check `context.user`",
      "Field-level vs object-level auth: returning a User object grants access to all fields unless guards exist on `email`/`role`/etc.",
      "Disabled introspection in prod — leaving it on leaks the full schema (informational severity)",
      "Query depth/complexity limits stop abusive nested queries; absence is the bug",
      "Aliasing + batching can multiply the cost of an unauthenticated query — expensive resolvers need rate limits",
    ],
  },
  {
    tag: "socketio",
    title: "Socket.IO",
    languages: JS_LANGS,
    bullets: [
      "`io.use(authMiddleware)` is the auth gate; absent or post-route registrations leave events unauthenticated",
      "`socket.on('event', handler)` payloads are user input — validate before persisting / emitting",
      "`socket.handshake.auth` is client-supplied; rely on the validated session, not the handshake claim",
      "Broadcasting to a room without scoping to the authenticated user is cross-tenant data leakage",
    ],
  },
  {
    tag: "bullmq",
    title: "BullMQ",
    languages: JS_LANGS,
    bullets: [
      "`job.data` is whatever the producer enqueued — treat it as user input if any web handler can enqueue",
      "Workers run with elevated trust (no auth context) — confirm the queue boundary validates / authorizes the request before enqueue",
      "Retry on poison messages can amplify a single attacker payload across retries — flag handlers without idempotency keys",
      "`Queue.add(..., { delay })` at long delays plus user-controlled payload = stored-XSS-via-job",
    ],
  },
  {
    tag: "bun",
    title: "Bun",
    languages: JS_LANGS,
    bullets: [
      "`Bun.serve({ fetch })` is a raw HTTP entry — auth/validation lives entirely in the handler, no framework gates",
      "`Bun.spawn(...)` / `Bun.$`...`` shell template — interpolated user input is RCE-shaped",
      "Bun's TLS/HTTP defaults differ from Node; verify rejected-cert handling on outbound `fetch`",
    ],
  },
  {
    tag: "deno",
    title: "Deno",
    languages: JS_LANGS,
    bullets: [
      "`Deno.serve(handler)` is the entry; no built-in auth — middleware order is hand-rolled",
      "Permissions (`--allow-net`, `--allow-read`, `--allow-env`) are deploy-time; code that calls `Deno.permissions.request` at runtime is suspicious",
      "Oak `ctx.request.body()` / `ctx.params` are untrusted; same sinks as Express",
    ],
  },
  {
    tag: "workers",
    title: "Cloudflare Workers / Edge",
    languages: JS_LANGS,
    bullets: [
      "`export default { fetch(req, env, ctx) }` is the only entry — auth lives in `fetch`, no framework gates",
      "`env.<BINDING>` exposes KV / R2 / D1 / secrets — review whether bindings are over-permissioned",
      "Workers can't `require('fs')` / `child_process`; common Node patterns are absent (verify imports compile in Workers runtime)",
      "`caches.default` keys include the full URL — query strings poison the cache unless normalized",
    ],
  },
  {
    tag: "symfony",
    title: "Symfony",
    languages: ["php"],
    bullets: [
      "Routes without `#[IsGranted]` or `security:` config are public — confirm controller/method has an auth gate",
      "`$request->get('x')` / `$request->query->get('x')` / `$request->request->get('x')` are user input",
      "Twig auto-escapes by default; `|raw` filter or `{% autoescape false %}` blocks are XSS sinks",
      "`#[Route(requirements: ['id' => '\\d+'])]` regex constraints are easy to fool — auth checks must use the resolved entity, not the param",
      "`security.yaml` `access_control` rules match top-down; a permissive earlier rule defeats a stricter later one",
    ],
  },
  {
    tag: "slim",
    title: "Slim",
    languages: ["php"],
    bullets: [
      "Slim has no built-in auth — middleware via `->add(...)` order matters; routes outside the `->group(...)` aren't covered",
      "`$request->getQueryParams()` / `getParsedBody()` / `getAttribute()` are user input",
      "`->add()` order is reversed at execution: last-added runs first; flag routes with auth middleware added BEFORE logging",
    ],
  },
  {
    tag: "yii",
    title: "Yii",
    languages: ["php"],
    bullets: [
      "Every `actionXxx()` on a Controller is publicly accessible by default — `behaviors()` is the place to wire AccessControl",
      "`Yii::$app->request->post('x')` / `get('x')` are user input; mass assignment via `$model->load($data)` is the bug if `safeAttributes()` isn't restricted",
      "`Html::encode()` is the safe form; `Html::decode()` and `echo $userInput` are XSS sinks",
      "AR query: `findOne(['id' => $id])` is parameterized; raw `Yii::$app->db->createCommand(\"...$id...\")` is SQL injection",
    ],
  },
  {
    tag: "cakephp",
    title: "CakePHP",
    languages: ["php"],
    bullets: [
      "`$this->Auth->allow(...)` opens specific actions to the public — confirm the list is intentional",
      "`$this->request->getData()` is user input; mass assignment via `patchEntity()` without `accessibleFields` is the bug",
      "Bake-generated views use `h($x)` for escape — flag templates that emit raw `$x` without `h()`",
      "`->find()->where(['col' => $x])` is parameterized; `->find()->where(\"col = '$x'\")` is SQLi",
    ],
  },
  {
    tag: "codeigniter",
    title: "CodeIgniter",
    languages: ["php"],
    bullets: [
      "Filters in `app/Config/Filters.php` are the auth gate; routes outside the filter scope are public",
      "`$this->request->getVar('x')` / `getPost()` are user input — concatenation into SQL via `$db->query(\"...$x...\")` is injection",
      "`view('name', $data)` auto-escapes; setting the third arg to disable escape requires explicit trust review",
      "`helper()` and `service()` calls can load arbitrary code if names are user-influenced",
    ],
  },
  {
    tag: "wordpress",
    title: "WordPress",
    languages: ["php"],
    bullets: [
      "`wp_ajax_nopriv_*` actions are unauthenticated by design — sensitive operations belong on `wp_ajax_*` only",
      "`'permission_callback' => '__return_true'` on `register_rest_route` is a public route — confirm intent",
      '`$wpdb->query("... $user_input ...")` is SQL injection; `$wpdb->prepare()` with placeholders is the safe form',
      "`wp_redirect($_GET['redirect'])` without `wp_validate_redirect()` is open-redirect",
      "Capability checks (`current_user_can()`) gate admin actions — flag handlers that skip them",
    ],
  },
  {
    tag: "drupal",
    title: "Drupal",
    languages: ["php"],
    bullets: [
      "`*.routing.yml` `_permission`/`_access` keys are the gate — `access content` is permissive (most authenticated users have it)",
      "`\\Drupal::request()->query->get('x')` / `request->get('x')` are user input",
      "`$this->t('@name', ['@name' => $userInput])` auto-escapes via `@`/`%`; bare placeholders without prefix are unsafe",
      "`db_query(\"... $x\")` is SQL injection; `\\Drupal::database()->query('... :x', [':x' => $x])` is parameterized",
    ],
  },
  {
    tag: "magento",
    title: "Magento",
    languages: ["php"],
    bullets: [
      "ACL via `etc/acl.xml`; webapi routes via `etc/webapi.xml` `<resources>` — flag routes set to `anonymous` doing sensitive work",
      "`$this->getRequest()->getParam('x')` is user input",
      "Plugin/observer code runs in core context — privilege escalation is easy if input isn't sanitized",
      "Customer data via `\\Magento\\Customer\\Api` requires customer ID; flag any read using user-supplied ID without ownership check",
    ],
  },
  {
    tag: "starlette",
    title: "Starlette",
    languages: ["python"],
    bullets: [
      "Auth lives in `AuthenticationMiddleware` + a backend; routes without it are public",
      "`Mount('/sub', app)` composes apps — the child app inherits NO middleware unless re-applied",
      "`request.query_params` / `request.json()` / `request.form()` are user input; same sinks as FastAPI",
      "WebSocketRoute handlers run on a long-lived connection — auth check should be on the OPEN handshake, not after",
    ],
  },
  {
    tag: "aiohttp",
    title: "aiohttp",
    languages: ["python"],
    bullets: [
      "Middleware via `@web.middleware` runs in declaration order — auth before logging is the safe layout",
      "`request.query` / `request.json()` / `request.match_info` / `request.read()` are user input",
      "`aiohttp_session` cookies need an explicit storage backend with secret rotation; default `EncryptedCookieStorage` is fine",
      "ClientSession (outbound) — flag user-controlled URLs without an allowlist (SSRF)",
    ],
  },
  {
    tag: "tornado",
    title: "Tornado",
    languages: ["python"],
    bullets: [
      "`@tornado.web.authenticated` is the auth gate — handlers without it are public; `get_current_user()` must be implemented per app",
      "`self.get_argument('x')` / `self.get_body_argument(...)` are user input",
      "Tornado templates auto-escape by default; `{% raw x %}` is the explicit unescape sink",
      "`tornado.escape.xhtml_escape` is the safe form for HTML; absence on user-influenced content is XSS",
    ],
  },
  {
    tag: "sanic",
    title: "Sanic",
    languages: ["python"],
    bullets: [
      "`@app.middleware('request')` runs on every request — flag auth checks that only run on specific blueprints",
      "`request.args` / `request.json` / `request.form` / `request.files` are user input",
      "`response.html()` does NOT auto-escape — use a templating layer or sanitize",
      "Worker count + concurrency means request-local state via globals is unsafe",
    ],
  },
  {
    tag: "bottle",
    title: "Bottle",
    languages: ["python"],
    bullets: [
      "Bottle has no built-in auth — every `@route` is public unless a decorator chain enforces a check",
      "`request.query` / `request.forms` / `request.json` are user input",
      "SimpleTemplate `{{!x}}` is unescaped; `{{x}}` auto-escapes — flag the bang form",
      "`static_file(filename, root)` without `path.basename(filename)` is path traversal",
    ],
  },
  {
    tag: "falcon",
    title: "Falcon",
    languages: ["python"],
    bullets: [
      "`on_<method>(self, req, resp, ...)` handlers are public unless a middleware/hook checks auth",
      "`req.media` / `req.params` / `req.get_param('x')` are user input",
      "`req.context` carries auth-claim data — confirm it's set BEFORE the resource handler runs",
      "Falcon's `resp.media` accepts dicts directly; over-fetching DB rows leaks PII",
    ],
  },
  {
    tag: "celery",
    title: "Celery",
    languages: ["python"],
    bullets: [
      "Task args are deserialized via the configured serializer — `pickle` is unsafe deserialization (RCE)",
      "Tasks run with worker-level trust (no request user) — re-validate ownership when a task acts on user data",
      "`task.delay(user_id=...)` invocations from web code: confirm the call site authenticates the user before enqueue",
      "Long retries on poison messages can amplify a single bad payload",
    ],
  },
  {
    tag: "airflow",
    title: "Airflow",
    languages: ["python"],
    bullets: [
      "DAGs run with the Airflow scheduler's privileges — operator template fields (`{{ params.x }}`) interpolated into Bash/SQL/HTTP are injection sinks",
      '`BashOperator(bash_command=f"... {x}")` is shell injection — even non-templated f-strings are risky if x is user-influenced',
      "Connections and Variables hold credentials — leaking them via XCom or logs is data exposure",
      "REST API auth (`auth_backends`) — defaults can be permissive on older versions",
    ],
  },
  {
    tag: "sinatra",
    title: "Sinatra",
    languages: ["ruby"],
    bullets: [
      "No built-in auth — every `get '/path' do ... end` is public unless a `before do ... end` hook enforces a check",
      '`params[:x]` is user input — concatenation into SQL via `Sequel.lit("...#{x}...")` or `where("col = \'#{x}\'")` is SQLi',
      "`erb` templates auto-escape only when `escape_html: true` is set; the default is OFF — confirm the setting",
      "`send_file(params[:f])` without a path containment check is path traversal",
    ],
  },
  {
    tag: "grape",
    title: "Grape",
    languages: ["ruby"],
    bullets: [
      "Auth lives in `before do ... end` or `helpers do ... end` — endpoints without it are public",
      "`params` is the only safe input accessor; raw `request.body.read` skips Grape's coercion",
      "`declared(params, include_missing: false)` is strong-params equivalent — flag handlers that use `params` directly for mass assignment",
      "API versioning paths (`version 'v1'`) — confirm deprecated versions still enforce auth",
    ],
  },
  {
    tag: "hanami",
    title: "Hanami",
    languages: ["ruby"],
    bullets: [
      "Each `Hanami::Action` subclass is publicly addressable via the router — `before` callbacks are the auth gate",
      "Strong-params equivalent: `params.valid?` + a Contract — handlers using raw `params` skip validation",
      "`include Deps[...]` for DI: shared DB / repo objects can leak ownership semantics if used as singletons",
    ],
  },
  {
    tag: "roda",
    title: "Roda",
    languages: ["ruby"],
    bullets: [
      "Roda uses a routing tree (`r.on`/`r.is`/`r.get`...) — auth must be at the tree node that wraps the handler, not just at the leaf",
      "`r.params` is user input; same sinks as Sinatra",
      "Plugins (`plugin :csrf`, `plugin :authentication`) are off by default — confirm they're loaded",
      "`r.run(other_app)` mounts subapps — they don't inherit the parent tree's auth automatically",
    ],
  },
  {
    tag: "gorilla",
    title: "Gorilla mux",
    languages: ["go"],
    bullets: [
      "`router.Use(authMiddleware)` covers the router; subrouters via `Subrouter()` inherit, but `PathPrefix(...).Handler(other)` does not",
      "`mux.Vars(r)` is user input — usual injection sinks (SQL, exec, fs, URL)",
      '`router.HandleFunc("/x", h).Methods("GET")` — flag handlers without an explicit `.Methods` (accept any verb)',
    ],
  },
  {
    tag: "buffalo",
    title: "Buffalo",
    languages: ["go"],
    bullets: [
      "`app.Use(...)` middleware is global; `app.Resource(...)` registers CRUD — confirm auth wraps both",
      "`c.Param('x')` / `c.Request()` / `c.Bind(&v)` are user input",
      "`render.Auto` chooses HTML / JSON / XML by Accept header — DB rows in the response include all columns; use a response shape",
    ],
  },
  {
    tag: "cobra",
    title: "Cobra",
    languages: ["go"],
    bullets: [
      "Privileged CLI surface — flags often hold secrets (`--token`, `--password`); flag any logging of `cmd.Flags()`",
      "`Run`/`RunE` handlers operate with the operator's privileges; user-supplied args interpolated into shell or SQL are injection",
      "`PersistentFlags` propagate to subcommands — credential flags on a parent leak to all children",
    ],
  },
  {
    tag: "actix",
    title: "Actix-web",
    languages: ["rust"],
    bullets: [
      "Middleware via `App::new().wrap(...)` is global; per-scope wraps via `web::scope().wrap()` — flag scopes with skipped wraps",
      "Extractors `web::Query<T>` / `web::Json<T>` / `web::Path<T>` are user input — types only validate STRUCTURE, not content",
      "Auth middleware that returns `next.call(req)` unconditionally before the check is the bypass shape",
      '`HttpResponse::Ok().body(format!("<html>{}</html>", x))` is XSS — use a templating crate with escape',
    ],
  },
  {
    tag: "axum",
    title: "Axum",
    languages: ["rust"],
    bullets: [
      '`Router::new().route("/", get(h)).layer(auth_layer)` — `.layer` order matters; routes added AFTER `.layer` may not be wrapped',
      "`Extension<User>` / `State<App>` carry auth identity — flag handlers that skip them",
      "`Path<T>` / `Query<T>` / `Json<T>` extractors are user input; same sinks as Actix",
      "`.merge(other_router)` and `.nest(prefix, other)` — sub-routers inherit parent layers but the order of `.layer` vs `.merge`/`.nest` matters",
    ],
  },
  {
    tag: "rocket",
    title: "Rocket",
    languages: ["rust"],
    bullets: [
      "Request guards are the auth gate (`fn from_request(...) -> Outcome<...>`) — handlers without a guard are public",
      "`#[derive(FromForm)]` / `Json<T>` deserialize user input — types validate structure only",
      "`#[catch(404)]` and similar can leak internal info if the catcher renders raw error data",
      "Fairings (Rocket middleware) have lifecycle hooks; `on_request` running BEFORE auth guard is the wrong layer for security",
    ],
  },
  {
    tag: "warp",
    title: "Warp",
    languages: ["rust"],
    bullets: [
      "Filters compose via `.and(...)` — auth filter must precede the body extractor in the chain",
      "`warp::path!()` macro — patterns end-anchor by default, but `warp::any()` matches everything (review uses)",
      "`warp::body::content_length_limit(N)` is essential; absent uses can DoS the server",
      "Error rejections via `Rejection` — confirm error responses don't leak internal types/messages",
    ],
  },
  {
    tag: "tide",
    title: "Tide",
    languages: ["rust"],
    bullets: [
      "Middleware via `app.with(...)` runs in registration order — auth before logging is right",
      "`req.body_json::<T>()` / `req.query::<T>()` / `req.param('x')` are user input",
      "Tide's response macros don't HTML-escape — explicit escaping is the dev's responsibility",
    ],
  },
  {
    tag: "poem",
    title: "Poem",
    languages: ["rust"],
    bullets: [
      "`#[handler]` functions have type-driven extractors (`Json`, `Query`, `Path`) — extractors validate structure, not content",
      "Endpoint composition via `.with(middleware)` and `.around(handler_fn)` — middleware must wrap the auth path",
      "`OpenApiService` exposes the schema — confirm prod doesn't ship Swagger UI on a sensitive route",
    ],
  },
  {
    tag: "tonic",
    title: "Tonic (gRPC)",
    languages: ["rust"],
    bullets: [
      "Per-method auth via `Interceptor` is the right gate; absent or method-skipping interceptors leave RPCs unauthenticated",
      "`Request<T>` body deserializes via prost — type-safe, but unbounded `repeated`/`bytes` fields can DoS the server",
      "Streaming RPCs (`tonic::Streaming<T>`) — auth check at stream open, not on each message",
      "`Status::unauthenticated()` / `permission_denied()` are the canonical denials — confirm code uses them, not generic `internal`",
    ],
  },
  {
    tag: "lambda-rs",
    title: "Rust AWS Lambda",
    languages: ["rust"],
    bullets: [
      "`LambdaEvent<T>::payload` is API Gateway / SQS / etc. payload — type-driven but content is user-supplied",
      "`event.payload.request_context.authorizer` carries claims when API Gateway authorizer is configured — handler must verify",
      "Cold-start global state (lazy_static / OnceCell) survives across invocations — credentials/state leakage between tenants",
    ],
  },
  {
    tag: "spring",
    title: "Spring",
    languages: ["java", "kotlin"],
    bullets: [
      "`SecurityFilterChain` / `HttpSecurity.authorizeHttpRequests` is the gate — `permitAll()` on a sensitive path is the bug",
      '`@PreAuthorize("...SpEL...")` evaluates against the authenticated principal; flag handlers without it',
      "`@RequestParam` / `@PathVariable` / `@RequestBody` are user input — Bean validation (`@Valid`) only checks structure",
      "`@ResponseBody` returning entity classes can over-expose DB columns; use a DTO",
      'CORS config (`@CrossOrigin("*")`) with credentials enabled is CSRF-via-fetch',
    ],
  },
  {
    tag: "ktor",
    title: "Ktor",
    languages: ["kotlin"],
    bullets: [
      '`authenticate("jwt") { ... }` blocks are the gate — routes outside them are public',
      "`call.receive<T>()` deserializes user input — `kotlinx.serialization` is structure-validating, not content-validating",
      "`call.parameters` / `call.request.queryParameters` are user input",
      "Status pages plugin handles errors — confirm prod config doesn't echo exceptions to the response",
    ],
  },
  {
    tag: "micronaut",
    title: "Micronaut",
    languages: ["java", "kotlin"],
    bullets: [
      "`@Secured(SecurityRule.IS_AUTHENTICATED)` on controller is the gate; `@PermitAll` opens it back up",
      "`@Body` / `@QueryValue` / `@PathVariable` are user input",
      "Reactive endpoints return `Mono`/`Flux` — auth check must be in the reactive chain, not just the handler signature",
      "Bean introspection (compile-time DI) means runtime config can't easily swap auth — flag config-driven gates",
    ],
  },
  {
    tag: "jaxrs",
    title: "JAX-RS (Jersey/Quarkus/RESTEasy)",
    languages: ["java", "kotlin"],
    bullets: [
      "`@RolesAllowed`/`@DenyAll`/`@PermitAll` are the gate; absence on a `@Path` resource is public",
      "`@QueryParam`/`@PathParam`/`@FormParam`/`@HeaderParam` are user input",
      "`@RequestScoped` provider classes can leak per-request state if held by `@ApplicationScoped` resources",
      "`Response.ok(entity)` with raw JPA entities over-fetches columns; use a DTO",
    ],
  },
  {
    tag: "dotnet",
    title: ".NET / ASP.NET Core",
    languages: ["csharp"],
    bullets: [
      "`[Authorize]` is the gate; `[AllowAnonymous]` on a sensitive action opens it back up — confirm intent",
      "`[FromQuery]` / `[FromBody]` / `[FromRoute]` are user input — model binding is structure-only",
      "`[ApiController]` adds automatic 400 on model-state errors; absence means the handler MUST check `ModelState.IsValid`",
      "Razor `@Html.Raw(x)` on user input is XSS; bare `@x` HTML-encodes (safe)",
      "Minimal API `app.MapGet(...).RequireAuthorization()` is the gate — flag chains without it on sensitive routes",
      'EF Core `FromSqlRaw($"... {x} ...")` is SQLi; `FromSqlInterpolated($"... {x} ...")` parameterizes correctly',
    ],
  },
  {
    tag: "azure-functions",
    title: "Azure Functions",
    languages: ["csharp", "javascript", "typescript", "python"],
    bullets: [
      "`AuthorizationLevel.Anonymous` on `HttpTrigger` is a public endpoint — confirm intent; `Function`/`Admin` require a function key",
      "Function keys are NOT user identity — they authenticate the *caller app*, not a user; for user auth use Easy Auth or App Service Authentication",
      "Triggers (Queue/ServiceBus/Blob) are reached via Azure infra — payloads are still user input if any web caller can write to the queue",
      'Bindings (e.g. `[Blob("path/{queueTrigger}")]`) interpolate input into resource paths — can be path traversal across containers',
    ],
  },
  {
    tag: "phoenix",
    title: "Phoenix (Elixir)",
    languages: ["elixir"],
    bullets: [
      "Pipelines (`pipeline :api do plug :auth_token end`) are the gate; routes in a `scope` without the right pipeline are public",
      '`conn.params` / `conn.body_params` are user input; raw `Repo.query!("... #{x}")` is SQLi (`Ecto.Adapters.SQL.query!` parameterized form is the safe one)',
      "`Phoenix.HTML.raw(x)` skips escaping — XSS sink",
      'LiveView `handle_event("name", params, socket)` runs server-side — flag handlers that don\'t authorize the action against `socket.assigns.current_user`',
      "Routes can use `live_session` with `on_mount` for auth — verify the on_mount auth check actually runs",
    ],
  },
  {
    tag: "kemal",
    title: "Crystal Kemal",
    languages: [],
    bullets: [
      "No built-in auth — every `get '/path' do ... end` is public unless a `before_*` filter intercepts",
      '`env.params.url["x"]` / `env.params.json["x"]` / `env.params.body["x"]` are user input',
      "Crystal's macro-driven JSON parsing is type-safe but content-unvalidated; bounds checks on collections matter",
    ],
  },
  {
    tag: "clojure",
    title: "Clojure (Ring/Compojure)",
    languages: [],
    bullets: [
      "Ring middleware composes via `wrap-*`; auth must be in the chain BEFORE the route handler",
      "`wrap-anti-forgery` (CSRF) is opt-in — flag apps using session cookies without it",
      'Compojure `(GET "/x" [id] ...)` destructures params; `(get-in request [:params :x])` is the same — both untrusted',
      "`ring.util.response/redirect` to user-controlled paths is open-redirect without an allowlist",
    ],
  },
  {
    tag: "erlang",
    title: "Erlang (Cowboy)",
    languages: [],
    bullets: [
      "`init/2` is the cowboy entry — auth check must happen before any state-changing call",
      "`cowboy_req:binding(name, Req)` / `read_body/1` / `parse_qs/1` are user input",
      "Erlang term decoding from external sources via `binary_to_term/1` is unsafe deserialization — use `binary_to_term/2` with `[safe]`",
      "Process-per-request model isolates handler crashes, but supervision-tree restart strategies can hide errors",
    ],
  },
  {
    tag: "vapor",
    title: "Swift Vapor",
    languages: [],
    bullets: [
      "Auth via middleware: `app.grouped(User.guardMiddleware()).get(...)` — routes outside the grouped scope are public",
      '`req.parameters.get("x")` / `req.query` / `req.content.decode(...)` are user input',
      'Fluent (Vapor\'s ORM) — raw SQL via `req.db.raw("... \\(x)")` is injection; `.where(\\.$name == x)` is parameterized',
      "Sessions (`req.session.data`) and JWTs (`req.jwt.verify(...)`) — verify signature algorithm pinning",
    ],
  },
  {
    tag: "dart",
    title: "Dart (Shelf)",
    languages: [],
    bullets: [
      "Shelf has no built-in auth — `Pipeline().addMiddleware()` is the gate, registration order matters",
      "`request.url.queryParameters` / `request.readAsString()` are user input",
      "`Response.ok(body)` doesn't HTML-escape; templates need explicit escape if rendering HTML",
      "`io.serve(handler, ...)` exposes the handler directly — no framework gates beyond what you write",
    ],
  },
  {
    tag: "apex",
    title: "Apex (Salesforce)",
    languages: [],
    bullets: [
      "`without sharing` classes BYPASS row-level security — confirm every `without sharing` is intentional and that the methods can't be invoked by unprivileged users",
      "`@AuraEnabled` methods are reachable from Lightning components without extra auth — same surface as REST",
      "`Database.query('SELECT ... WHERE ... = \\'' + userInput + '\\'')` is SOQL injection; `[SELECT ... WHERE id = :userInput]` is bound and safe",
      "FLS / CRUD checks (`Schema.sObjectType.X.isAccessible()`) are NOT automatic — flag DML on sObjects without explicit checks",
      "`@RestResource(urlMapping='...')` exposes the class on `/services/apexrest/` — public to authenticated Salesforce users; confirm the data filter",
    ],
  },
  {
    tag: "aws-lambda",
    title: "AWS Lambda",
    languages: [],
    bullets: [
      "API Gateway authorizer claims live on `event.requestContext.authorizer` — handlers that don't read them are unauthenticated",
      "`event.body` is JSON-string in proxy integrations — JSON.parse failures should NOT echo `event` (leaks request data into logs)",
      "IAM role on the function determines blast radius — over-permissioned roles + RCE = account takeover",
      "Cold-start global state is shared across invocations on the same container — credentials/PII can leak between tenants",
      "Lambda timeouts default to 3s but can be 15min — long-running handlers without per-call rate limits enable cost amplification",
    ],
  },
  {
    tag: "gcp-cloud-functions",
    title: "GCP Cloud Functions",
    languages: [],
    bullets: [
      "Allow-unauthenticated invocations (`--allow-unauthenticated`) make the function public — confirm via deploy config",
      "IAM-based auth (Cloud IAM) is invoker-level; for user identity, integrate Identity Platform / Firebase Auth in the handler",
      "Function URLs include the project ID and region — leakage of these is information disclosure",
      "Background functions (Pub/Sub, Storage triggers) — payload comes from the GCP infra but is still ATTACKER-INFLUENCED if any web path can write to the bucket/topic",
    ],
  },
  {
    tag: "android",
    title: "Android",
    languages: [],
    bullets: [
      '`android:exported="true"` on Activity/Service/Receiver/Provider exposes the component to other apps — confirm with intent + permission',
      'Implicit `<intent-filter>` makes a component exported on pre-API-31 even without `android:exported="true"` — flag legacy code',
      'Deeplink schemes (`<data android:scheme="..."/>`) — review URL handling for SSRF (WebView), file:// loads, JS bridges',
      "`WebView` with `setJavaScriptEnabled(true)` + `addJavascriptInterface` is RCE if the loaded URL is attacker-controlled",
      'ContentProvider exported without permission grants reads/writes to any app — `android:grantUriPermissions="true"` widens scope further',
    ],
  },
  {
    tag: "ios",
    title: "iOS",
    languages: [],
    bullets: [
      "`CFBundleURLSchemes` registers your app as a URL handler — `application(_:open:)` / `scene(_:openURLContexts:)` receive attacker-controlled URLs",
      "Universal Links via `apple-app-site-association` — host association determines which domains can open the app; misconfig is account-takeover-shaped",
      "WKWebView with `loadHTMLString(html, baseURL:)` and a `file://` baseURL gives the page access to local files",
      "Keychain access without `kSecAttrAccessibleWhenUnlocked` (or stricter) leaks credentials at app launch",
      "App Transport Security exceptions in Info.plist (`NSAllowsArbitraryLoads`) downgrade TLS — flag any plist that opts out",
    ],
  },
];

const HIGHLIGHTS_BY_TAG = new Map<string, TechHighlight>(TECH_HIGHLIGHTS.map((h) => [h.tag, h]));

export function highlightForTag(tag: string): TechHighlight | undefined {
  return HIGHLIGHTS_BY_TAG.get(tag);
}

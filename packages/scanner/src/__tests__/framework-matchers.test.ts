import { describe, expect, it } from "vitest";
import { goChiRouteMatcher } from "../matchers/go-chi-route.js";
import { goEchoRouteMatcher } from "../matchers/go-echo-route.js";
import { goFiberRouteMatcher } from "../matchers/go-fiber-route.js";
import { goGinRouteMatcher } from "../matchers/go-gin-route.js";
import { jsExpressRouteMatcher } from "../matchers/js-express-route.js";
import { jsFastifyRouteMatcher } from "../matchers/js-fastify-route.js";
import { jsHonoRouteMatcher } from "../matchers/js-hono-route.js";
import { jsNestjsControllerMatcher } from "../matchers/js-nestjs-controller.js";
import { laravelBladeXssMatcher } from "../matchers/laravel-blade-xss.js";
import { laravelConfigExposureMatcher } from "../matchers/laravel-config-exposure.js";
import { laravelLivewireFilamentMatcher } from "../matchers/laravel-livewire-filament.js";
import { laravelMassAssignmentMatcher } from "../matchers/laravel-mass-assignment.js";
import { laravelMissingAuthorizationMatcher } from "../matchers/laravel-missing-authorization.js";
import { laravelSqlRawMatcher } from "../matchers/laravel-sql-raw.js";
import { laravelUnsafeSinksMatcher } from "../matchers/laravel-unsafe-sinks.js";
import { phpLaravelRouteMatcher } from "../matchers/php-laravel-route.js";
import { pyDjangoViewMatcher } from "../matchers/py-django-view.js";
import { pyFastapiRouteMatcher } from "../matchers/py-fastapi-route.js";
import { pyFlaskRouteMatcher } from "../matchers/py-flask-route.js";
import { rbRailsControllerMatcher } from "../matchers/rb-rails-controller.js";

describe("framework entry-point matchers", () => {
  it("js-express-route detects app.get / router.use signatures", () => {
    const src = `
import express from "express";
const app = express();
app.get("/users", (req, res) => res.json({}));
app.post("/login", async (req, res, next) => {});
const router = express.Router();
router.use(authMiddleware);
`;
    const matches = jsExpressRouteMatcher.match(src, "src/server.ts");
    expect(matches.length).toBeGreaterThan(0);
    expect(matches.map((m) => m.matchedPattern).join(" ")).toMatch(/method|handler/);
  });

  it("js-fastify-route detects fastify.get / instance.register", () => {
    const src = `
import Fastify from "fastify";
const app = Fastify();
app.get("/", async () => "ok");
app.route({ method: "POST", url: "/x", handler });
app.addHook("preHandler", async (request, reply) => {});
`;
    const matches = jsFastifyRouteMatcher.match(src, "src/index.ts");
    expect(matches.length).toBeGreaterThan(0);
  });

  it("js-nestjs-controller detects @Controller / @Get / @UseGuards", () => {
    const src = `
import { Controller, Get, UseGuards, Body } from "@nestjs/common";

@Controller("users")
export class UsersController {
  @UseGuards(JwtGuard)
  @Get(":id")
  findOne(@Body() body: any) {}
}
`;
    const matches = jsNestjsControllerMatcher.match(src, "src/users.controller.ts");
    expect(matches.length).toBeGreaterThan(0);
  });

  it("js-hono-route detects app.get + c.req.json", () => {
    const src = `
import { Hono } from "hono";
const app = new Hono();
app.get("/users", async (c) => c.json(await c.req.json()));
app.use("*", authMiddleware);
`;
    const matches = jsHonoRouteMatcher.match(src, "src/server.ts");
    expect(matches.length).toBeGreaterThan(0);
  });

  it("py-django-view detects path() / class-based views / @csrf_exempt", () => {
    const src = `
from django.urls import path
from django.views import View
from django.views.decorators.csrf import csrf_exempt

class FooView(View):
    def get(self, request):
        return HttpResponse("hi")

@csrf_exempt
def webhook(request):
    return HttpResponse("ok")

urlpatterns = [
    path("foo/", FooView.as_view()),
]
`;
    const matches = pyDjangoViewMatcher.match(src, "app/views.py");
    expect(matches.length).toBeGreaterThan(0);
  });

  it("py-fastapi-route detects @router.get / Depends", () => {
    const src = `
from fastapi import APIRouter, Depends
router = APIRouter()

@router.get("/me")
async def me(user = Depends(current_user)):
    return user
`;
    const matches = pyFastapiRouteMatcher.match(src, "app/main.py");
    expect(matches.length).toBeGreaterThan(0);
  });

  it("py-flask-route detects @app.route and Blueprint", () => {
    const src = `
from flask import Flask, Blueprint
app = Flask(__name__)
bp = Blueprint("api", __name__)

@app.route("/")
def index():
    return "hi"

@bp.get("/users")
def users():
    return []
`;
    const matches = pyFlaskRouteMatcher.match(src, "app/__init__.py");
    expect(matches.length).toBeGreaterThan(0);
  });

  it("rb-rails-controller detects controller class + before_action", () => {
    const src = `
class UsersController < ApplicationController
  before_action :authenticate_user!
  skip_before_action :verify_authenticity_token, only: [:webhook]

  def show
    user = User.find(params[:id])
    render json: user
  end
end
`;
    const matches = rbRailsControllerMatcher.match(src, "app/controllers/users_controller.rb");
    expect(matches.length).toBeGreaterThan(0);
  });

  it("php-laravel-route detects route registrations and controllers", () => {
    const src = `<?php
use Illuminate\\Support\\Facades\\Route;
use Illuminate\\Support\\Facades\\DB;

Route::get('/users', [UsersController::class, 'index']);
Route::resource('posts', PostsController::class);
Route::group(['middleware' => 'auth'], function () {
  Route::post('/admin', AdminController::class);
});

class UsersController extends Controller {
  public function search(Request $r) {
    return DB::raw("SELECT * FROM users WHERE name = '" . $r->name . "'");
  }
}
`;
    const matches = phpLaravelRouteMatcher.match(src, "app/Http/Controllers/UsersController.php");
    expect(matches.length).toBeGreaterThan(0);
  });

  it("go-gin-route detects r.GET and c.Query", () => {
    const src = `
package main

import "github.com/gin-gonic/gin"

func main() {
  r := gin.Default()
  api := r.Group("/api")
  api.GET("/users/:id", func(c *gin.Context) {
    id := c.Query("id")
    c.JSON(200, gin.H{"id": id})
  })
}
`;
    const matches = goGinRouteMatcher.match(src, "cmd/server/main.go");
    expect(matches.length).toBeGreaterThan(0);
  });

  it("go-echo-route detects e.GET and c.Bind", () => {
    const src = `
package main

import "github.com/labstack/echo/v4"

func main() {
  e := echo.New()
  e.GET("/users", func(c echo.Context) error {
    var u User
    return c.Bind(&u)
  })
}
`;
    const matches = goEchoRouteMatcher.match(src, "cmd/server/main.go");
    expect(matches.length).toBeGreaterThan(0);
  });

  it("go-fiber-route detects app.Get and c.BodyParser", () => {
    const src = `
package main

import "github.com/gofiber/fiber/v2"

func main() {
  app := fiber.New()
  app.Get("/users/:id", func(c *fiber.Ctx) error {
    var body struct{}
    return c.BodyParser(&body)
  })
}
`;
    const matches = goFiberRouteMatcher.match(src, "cmd/server/main.go");
    expect(matches.length).toBeGreaterThan(0);
  });

  it("go-chi-route detects r.Get / chi.URLParam / .Mount", () => {
    const src = `
package main

import (
  "github.com/go-chi/chi/v5"
  "net/http"
)

func main() {
  r := chi.NewRouter()
  r.Get("/users/{id}", func(w http.ResponseWriter, req *http.Request) {
    id := chi.URLParam(req, "id")
    _ = id
  })
  r.Mount("/api", apiRouter)
}
`;
    const matches = goChiRouteMatcher.match(src, "cmd/server/main.go");
    expect(matches.length).toBeGreaterThan(0);
  });
});

describe("laravel matchers (negative cases)", () => {
  const F = "app/Http/Controllers/PostController.php";

  it("mass-assignment ignores fillable and validated input", () => {
    const src = `protected $fillable = ['name'];\nUser::create($request->validated());\n$u->update($request->only('name'));`;
    expect(laravelMassAssignmentMatcher.match(src, "app/Models/User.php")).toEqual([]);
  });

  it("mass-assignment skips tests", () => {
    expect(
      laravelMassAssignmentMatcher.match("User::create($request->all());", "tests/Feature/X.php"),
    ).toEqual([]);
  });

  it("sql-raw ignores bound parameters and static raw expressions", () => {
    const src = `User::whereRaw('LOWER(email) = ?', [$email])->get();\nDB::raw('COUNT(*)');\n$q->orderBy('created_at');`;
    expect(laravelSqlRawMatcher.match(src, F)).toEqual([]);
  });

  it("sql-raw skips migrations", () => {
    expect(
      laravelSqlRawMatcher.match('DB::statement("ALTER TABLE $t");', "database/migrations/x.php"),
    ).toEqual([]);
  });

  it("blade-xss ignores escaped output and known-safe raw helpers", () => {
    const src = `{{ $comment->body }}\n{!! json_encode($x) !!}\n{!! $slot !!}\n{!! csrf_field() !!}\n{!! Js::from($x) !!}`;
    expect(laravelBladeXssMatcher.match(src, "resources/views/a.blade.php")).toEqual([]);
  });

  it("missing-authorization is quiet when the controller authorizes", () => {
    const src = `class PostController extends Controller {\n  public function destroy(Post $post) {\n    $this->authorize('delete', $post);\n    $post->delete();\n  }\n}`;
    expect(laravelMissingAuthorizationMatcher.match(src, F)).toEqual([]);
  });

  it("missing-authorization is quiet with a FormRequest but not a plain Request", () => {
    const withForm = `class C extends Controller {\n  public function store(StorePostRequest $request) {}\n}`;
    const plain = `class C extends Controller {\n  public function store(Request $request) {}\n}`;
    expect(laravelMissingAuthorizationMatcher.match(withForm, F)).toEqual([]);
    expect(laravelMissingAuthorizationMatcher.match(plain, F).length).toBe(1);
  });

  it("missing-authorization checks each action, not the whole file", () => {
    const src = `class PostController extends Controller {\n  public function store(StorePostRequest $request) {}\n  public function destroy(Post $post) {\n    $post->delete();\n  }\n}`;
    const [hit] = laravelMissingAuthorizationMatcher.match(src, F);
    expect(hit.lineNumbers).toEqual([3]);
  });

  it("missing-authorization ignores a bare Policy import", () => {
    const src = `use App\\Policies\\PostPolicy;\nclass C extends Controller {\n  public function destroy(Post $post) {}\n}`;
    expect(laravelMissingAuthorizationMatcher.match(src, F).length).toBe(1);
  });

  it("livewire-filament flags untyped public identity properties", () => {
    const src = `class EditPost extends Component {\n  public $postId;\n}`;
    expect(laravelLivewireFilamentMatcher.match(src, "app/Livewire/EditPost.php").length).toBe(1);
  });

  it("livewire-filament is quiet for locked properties with authorization", () => {
    const src = `class EditPost extends Component {\n  #[Locked]\n  public int $postId;\n  public function delete() { $this->authorize('delete', $p); }\n}`;
    expect(laravelLivewireFilamentMatcher.match(src, "app/Livewire/EditPost.php")).toEqual([]);
  });

  it("livewire-filament flags unlocked property and unauthorized action", () => {
    const src = `class EditPost extends Component {\n  public int $postId;\n  public function delete() { Post::find($this->postId)->delete(); }\n}`;
    expect(laravelLivewireFilamentMatcher.match(src, "app/Livewire/EditPost.php").length).toBe(2);
  });

  it("unsafe-sinks ignores named redirects, safe unserialize, and ->exec methods", () => {
    const src = `return redirect()->route('home');\nunserialize($p, ['allowed_classes' => false]);\n$pdo->exec($sql);`;
    expect(laravelUnsafeSinksMatcher.match(src, F)).toEqual([]);
  });

  it("config-exposure ignores env-driven config and .env.example", () => {
    const src = `'debug' => (bool) env('APP_DEBUG', false),\n'key' => env('APP_KEY'),\n'secure' => env('SESSION_SECURE_COOKIE'),`;
    expect(laravelConfigExposureMatcher.match(src, "config/app.php")).toEqual([]);
    expect(laravelConfigExposureMatcher.match("APP_DEBUG=true", ".env.example")).toEqual([]);
    expect(laravelConfigExposureMatcher.match("DB_PASSWORD=", ".env")).toEqual([]);
  });
});

describe("laravel matchers (edge cases)", () => {
  const F = "app/Http/Controllers/PostController.php";
  const labels = (ms: { matchedPattern: string }[]) => ms.map((m) => m.matchedPattern);

  it("sql-raw flags DB facade calls with request or property input", () => {
    for (const src of [
      "DB::raw($request->input('col'))",
      "DB::raw(request('col'))",
      "DB::select($this->sql)",
    ]) {
      expect(laravelSqlRawMatcher.match(src, F).length).toBe(1);
    }
  });

  it("mass-assignment flags two-step whole-request input once per line", () => {
    const twoStep = laravelMassAssignmentMatcher.match(
      "$data = $request->all();\nUser::create($data);",
      F,
    );
    expect(twoStep.map((m) => m.lineNumbers)).toEqual([[1]]);
    expect(laravelMassAssignmentMatcher.match("User::create($request->all());", F).length).toBe(1);
  });

  it("missing-authorization credits #[Authorize] to the method below it", () => {
    const src = `class C extends Controller {\n  public function update(Post $p) {\n    $p->save();\n  }\n  #[Authorize('delete', 'post')]\n  public function destroy(Post $post) {\n    $post->delete();\n  }\n}`;
    expect(laravelMissingAuthorizationMatcher.match(src, F)[0].lineNumbers).toEqual([2]);
  });

  it("missing-authorization ignores non-auth middleware and 404 aborts", () => {
    const throttle = `class C extends Controller {\n  public function __construct() { $this->middleware('throttle:6,1'); }\n  public function destroy(Post $post) {\n    $post->delete();\n  }\n}`;
    const notFound = `class C extends Controller {\n  public function destroy(Post $post) {\n    abort_if(!$post, 404);\n  }\n}`;
    expect(laravelMissingAuthorizationMatcher.match(throttle, F).length).toBe(1);
    expect(laravelMissingAuthorizationMatcher.match(notFound, F).length).toBe(1);
  });

  it("missing-authorization accepts 403 aborts and class-wide auth middleware", () => {
    const forbidden = `class C extends Controller {\n  public function destroy(Post $post) {\n    abort_unless($post->user_id === auth()->id(), 403);\n  }\n}`;
    const ctor = `class C extends Controller {\n  public function __construct() { $this->middleware('auth'); }\n  public function destroy(Post $post) {}\n}`;
    const hasMiddleware = `class C extends Controller implements HasMiddleware {\n  public static function middleware(): array { return [new Middleware('can:manage-posts')]; }\n  public function destroy(Post $post) {}\n}`;
    const resource = `class C extends Controller {\n  public function __construct() { $this->authorizeResource(Post::class); }\n  public function destroy(Post $post) {}\n}`;
    for (const src of [forbidden, ctor, hasMiddleware, resource]) {
      expect(laravelMissingAuthorizationMatcher.match(src, F)).toEqual([]);
    }
  });

  it("livewire-filament flags Nova resources that only take NovaRequest", () => {
    const src = `class Post extends Resource {\n  public function fields(NovaRequest $request) {\n    return [Text::make('Body')->asHtml()];\n  }\n}`;
    expect(labels(laravelLivewireFilamentMatcher.match(src, "app/Nova/Post.php"))).toEqual([
      "Admin Resource without policy/can*() overrides (verify a policy exists)",
      "->html()/->asHtml() renders unescaped HTML (XSS)",
    ]);
  });

  it("livewire-filament is quiet for resources with authorizedTo overrides", () => {
    const src = `class Post extends Resource {\n  public function authorizedToDelete(Request $request) { return false; }\n}`;
    expect(laravelLivewireFilamentMatcher.match(src, "app/Nova/Post.php")).toEqual([]);
  });

  it("livewire-filament skips model-typed and same-line locked properties", () => {
    const src = `class EditPost extends Component {\n  public Post $post;\n  #[Locked] public int $postId;\n}`;
    expect(laravelLivewireFilamentMatcher.match(src, "app/Http/Livewire/EditPost.php")).toEqual([]);
  });

  it("unsafe-sinks flags Redirect facade, Storage disks and response()->file", () => {
    for (const src of [
      "return Redirect::to($request->input('next'));",
      "Storage::disk('s3')->get($request->input('path'));",
      "return response()->file(request('path'));",
    ]) {
      expect(laravelUnsafeSinksMatcher.match(src, F).length).toBe(1);
    }
  });

  it("config-exposure skips empty $except stubs and TrimStrings", () => {
    const stub = `class VerifyCsrfToken extends Middleware {\n  protected $except = [\n    //\n  ];\n}`;
    const trim = `class TrimStrings extends Middleware {\n  protected $except = [\n    'password',\n  ];\n}`;
    expect(
      laravelConfigExposureMatcher.match(stub, "app/Http/Middleware/VerifyCsrfToken.php"),
    ).toEqual([]);
    expect(laravelConfigExposureMatcher.match(trim, "app/Http/Middleware/TrimStrings.php")).toEqual(
      [],
    );
  });

  it("config-exposure flags a multi-line non-empty $except list", () => {
    const src = `class VerifyCsrfToken extends Middleware {\n  protected $except = [\n    'stripe/*',\n  ];\n}`;
    const [hit] = laravelConfigExposureMatcher.match(
      src,
      "app/Http/Middleware/VerifyCsrfToken.php",
    );
    expect(hit.lineNumbers).toEqual([2]);
  });

  it("config-exposure reports an open dashboard gate once and catches ::auth callbacks", () => {
    const P = "app/Providers/HorizonServiceProvider.php";
    expect(
      labels(
        laravelConfigExposureMatcher.match("Gate::define('viewHorizon', fn ($user) => true);", P),
      ),
    ).toEqual(["Telescope/Horizon/Pulse dashboard open to everyone"]);
    expect(
      laravelConfigExposureMatcher.match("Horizon::auth(function ($request) { return true; });", P)
        .length,
    ).toBe(1);
  });

  it("php-laravel-route sentinel accepts laravel/framework and artisan only", () => {
    const accept = phpLaravelRouteMatcher.requires?.sentinelContains;
    expect(accept?.("composer.json", '{"require":{"laravel/framework":"^11"}}')).toBe(true);
    expect(accept?.("artisan", "")).toBe(true);
    expect(accept?.("composer.json", '{"require":{"laravel/prompts":"^0.3"}}')).toBe(false);
  });
});

import { describe, expect, it } from "vitest";
import { goChiRouteMatcher } from "../matchers/go-chi-route.js";
import { goEchoRouteMatcher } from "../matchers/go-echo-route.js";
import { goFiberRouteMatcher } from "../matchers/go-fiber-route.js";
import { goGinRouteMatcher } from "../matchers/go-gin-route.js";
import { jsExpressRouteMatcher } from "../matchers/js-express-route.js";
import { jsFastifyRouteMatcher } from "../matchers/js-fastify-route.js";
import { jsHonoRouteMatcher } from "../matchers/js-hono-route.js";
import { jsNestjsControllerMatcher } from "../matchers/js-nestjs-controller.js";
import { phpLaravelRouteMatcher } from "../matchers/php-laravel-route.js";
import { pyDjangoViewMatcher } from "../matchers/py-django-view.js";
import { pyFastapiRouteMatcher } from "../matchers/py-fastapi-route.js";
import { pyFlaskRouteMatcher } from "../matchers/py-flask-route.js";
import { rbAsyncWebSocketHandlerMatcher } from "../matchers/rb-async-websocket-handler.js";
import { rbFalconRackAppMatcher } from "../matchers/rb-falcon-rack-app.js";
import { rbGrpcServiceMatcher } from "../matchers/rb-grpc-service.js";
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

  it("rb-grpc-service detects service classes, methods, metadata, interceptors, and server bootstrap", () => {
    const src = `
class GreeterServer < Helloworld::Greeter::Service
  def lookup(request, call)
    token = call.metadata["authorization"]
  end
end

class AuthInterceptor < GRPC::ServerInterceptor
  def request_response(request: nil, call: nil, method: nil)
  end
end

server.handle(GreeterServer)
server.add_http2_port("0.0.0.0:50051", :this_port_is_insecure)
server.run_till_terminated
`;
    const matches = rbGrpcServiceMatcher.match(src, "lib/greeter_server.rb");
    expect(matches.length).toBeGreaterThanOrEqual(5);
  });

  it("rb-grpc-service ignores generated and vendored Ruby files", () => {
    const src = `
# Generated by the protocol buffer compiler. DO NOT EDIT!
class Greeter < Helloworld::Greeter::Service
end
`;
    expect(rbGrpcServiceMatcher.match(src, "lib/helloworld_services_pb.rb")).toEqual([]);
    expect(rbGrpcServiceMatcher.match(src, "vendor/bundle/ruby/greeter.rb")).toEqual([]);
    expect(rbGrpcServiceMatcher.match(src, "spec/greeter_server.rb")).toEqual([]);
    expect(rbGrpcServiceMatcher.match(src, "lib/greeter_server.rb")).toEqual([]);
  });

  it("rb-async-websocket-handler detects async websocket receive loops", () => {
    const src = `
Async::WebSocket::Adapters::Rack.open(env) do |connection|
  while message = connection.read
    handle_message(message.buffer)
  end
end
`;
    const matches = rbAsyncWebSocketHandlerMatcher.match(src, "lib/stream_handler.rb");
    expect(matches.length).toBeGreaterThanOrEqual(3);
  });

  it("rb-falcon-rack-app detects strong Falcon and Async service signals", () => {
    const src = `
require "falcon"
service = Falcon::Service.new
endpoint = Async::HTTP::Endpoint.parse("https://example.com")
`;
    const matches = rbFalconRackAppMatcher.match(src, "lib/server.rb");
    expect(matches.length).toBeGreaterThanOrEqual(3);
    expect(rbFalconRackAppMatcher.match(`run App.new\nmap "/api" do\nend\n`, "config.ru")).toEqual(
      [],
    );
  });

  it("php-laravel-route detects Route::get and DB::raw", () => {
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

import type { MatcherPlugin } from "../types.js";
import { isLaravelSkippablePath } from "./laravel-utils.js";
import { regexMatcher } from "./utils.js";

/**
 * Laravel route registrations and controller actions. Sentinel-gated on
 * `composer.json` requiring `laravel/framework`, or the presence of the
 * `artisan` script — avoids firing on random PHP repos.
 */
export const phpLaravelRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "php-laravel-route",
  description: "Laravel route registrations and controller actions (gated on Laravel)",
  filePatterns: ["**/routes/**/*.php", "**/app/Http/Controllers/**/*.php"],
  requires: {
    tech: ["laravel"],
    sentinelFiles: ["composer.json", "artisan"],
    sentinelContains: (path, content) =>
      path === "artisan" || /"laravel\/framework"\s*:/.test(content),
  },
  examples: [
    `Route::get('/users', [UsersController::class, 'index']);`,
    `Route::post("/login", [AuthController::class, "login"])->middleware('guest');`,
    `Route::match(['get', 'post'], '/x', $handler);`,
    `Route::resource('posts', PostsController::class);`,
    `Route::group(['middleware' => 'auth'], function () { /* ... */ });`,
    `class UsersController extends Controller { public function show($id) {} }`,
    `Route::get('/me', fn () => auth()->user())->middleware('auth:sanctum');`,
  ],
  match(content, filePath) {
    if (isLaravelSkippablePath(filePath)) return [];

    return regexMatcher(
      "php-laravel-route",
      [
        {
          regex: /Route::(get|post|put|patch|delete|any|match)\s*\(/,
          label: "Route::* registration",
        },
        { regex: /Route::resource\s*\(/, label: "Route::resource (CRUD)" },
        { regex: /Route::group\s*\(/, label: "Route::group (middleware scope)" },
        {
          regex: /class\s+\w+Controller\s+extends\s+\w*Controller\b/,
          label: "Controller class",
        },
        { regex: /->middleware\s*\(\s*['"]auth/, label: "Auth middleware (verify scope)" },
      ],
      content,
    );
  },
};

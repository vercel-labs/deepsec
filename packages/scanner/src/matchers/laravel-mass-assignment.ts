import type { MatcherPlugin } from "../types.js";
import { isLaravelSkippablePath } from "./laravel-utils.js";
import { regexMatcher } from "./utils.js";

const ALL_INPUT = String.raw`(?:\$request->|request\s*\(\s*\)->)(?:all|input)\s*\(\s*\)`;

/**
 * Eloquent mass assignment: unguarded models and whole-request writes.
 */
export const laravelMassAssignmentMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "laravel-mass-assignment",
  description:
    "Eloquent mass assignment — $guarded = [], unguard(), forceFill, or whole-request input into create/update/fill",
  filePatterns: ["**/app/**/*.php", "**/routes/**/*.php"],
  requires: { tech: ["laravel"] },
  examples: [
    `protected $guarded = [];`,
    `Model::unguard();`,
    `User::unguard();`,
    `Model::unguarded(fn () => User::create($data));`,
    `$user->forceFill($data)->save();`,
    `User::forceCreate($data);`,
    `User::create($request->all());`,
    `$user->update($request->input());`,
    `$post->fill(request()->all());`,
    `$data = $request->all();`,
  ],
  match(content, filePath) {
    if (isLaravelSkippablePath(filePath)) return [];
    return regexMatcher(
      "laravel-mass-assignment",
      [
        { regex: /\$guarded\s*=\s*\[\s*\]/, label: "$guarded = [] (every attribute assignable)" },
        {
          regex: /\b\w+::unguard(?:ed)?\s*\(/,
          label: "Model::unguard (disables mass-assignment protection)",
        },
        {
          regex: /->(?:forceFill|forceCreate)\s*\(|::forceCreate\s*\(/,
          label: "forceFill/forceCreate (bypasses $fillable)",
        },
        {
          regex: new RegExp(
            String.raw`(?:::|->)(?:create|updateOrCreate|firstOrCreate|firstOrNew|insert|upsert|update|fill)\s*\(\s*${ALL_INPUT}`,
          ),
          label: "Whole-request input into create/update/fill (mass assignment)",
        },
        {
          regex: new RegExp(
            String.raw`^(?!.*(?:::|->)(?:create|updateOrCreate|firstOrCreate|firstOrNew|insert|upsert|update|fill)\s*\().*${ALL_INPUT}`,
          ),
          label: "Whole-request input captured (check where it flows)",
        },
      ],
      content,
    );
  },
};

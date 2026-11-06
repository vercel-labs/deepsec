import type { MatcherPlugin } from "../types.js";
import { isLaravelSkippablePath } from "./laravel-utils.js";
import { regexMatcher } from "./utils.js";

const INP = String.raw`(?:\$request->|request\s*\()`;
// excludes ->exec(), Foo::exec(), $exec
const FN = String.raw`(?<![\w>:$])`;
const TAINTED_ARG = String.raw`\s*(?:\$|"[^"]*\$|(?:'[^']*'|"[^"]*")\s*\.\s*\$)`;

/**
 * Request input reaching file, network, redirect and process sinks in
 * Laravel apps, plus object deserialization.
 */
export const laravelUnsafeSinksMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "laravel-unsafe-sinks",
  description:
    "Laravel request input into file paths, outbound HTTP, redirects, shell commands, plus unserialize()",
  filePatterns: ["**/app/**/*.php", "**/routes/**/*.php"],
  requires: { tech: ["laravel"] },
  examples: [
    `$request->file('f')->storeAs('uploads', $request->file('f')->getClientOriginalName());`,
    `return Storage::disk('local')->download($request->input('path'));`,
    `return response()->download(public_path($request->file));`,
    `$res = Http::withToken($t)->get($request->input('url'));`,
    `return redirect($request->input('next'));`,
    `return redirect()->away($request->get('to'));`,
    `Process::run("convert " . $request->name);`,
    `shell_exec("ls " . $dir);`,
    `Artisan::call($request->input('cmd'));`,
    `$obj = unserialize($payload);`,
  ],
  match(content, filePath) {
    if (isLaravelSkippablePath(filePath)) return [];
    const re = (s: string) => new RegExp(s);
    return regexMatcher(
      "laravel-unsafe-sinks",
      [
        {
          regex:
            /(?:storeAs|storePubliclyAs|putFileAs|move)\s*\(.*getClientOriginal(?:Name|Extension)\s*\(/,
          label: "Client-supplied filename/extension in upload path (traversal, .php upload)",
        },
        {
          regex: re(
            String.raw`\b(?:Storage::(?:disk\s*\([^)]*\)->)?(?:get|put|download|delete|response|path|url|exists|move|copy|readStream)|response\(\)->(?:download|file)|public_path|storage_path)\s*\(\s*${INP}`,
          ),
          label: "Request input in file path (path traversal)",
        },
        {
          regex: re(
            String.raw`\bHttp::(?:[^;]{0,200}->)?(?:get|post|put|patch|delete|head|send)\s*\(\s*${INP}`,
          ),
          label: "Request input as outbound HTTP URL (SSRF)",
        },
        {
          regex: re(
            String.raw`\bredirect\s*\(\s*${INP}|\bredirect\s*\(\s*\)->(?:to|away)\s*\(\s*${INP}|\bRedirect::(?:to|away)\s*\(\s*${INP}`,
          ),
          label: "Redirect to request input (open redirect)",
        },
        {
          regex: re(String.raw`\bProcess::(?:run|start|command|pipe)\s*\(${TAINTED_ARG}`),
          label: "Process facade with interpolated/variable command (command injection)",
        },
        {
          regex: re(
            String.raw`${FN}(?:exec|shell_exec|system|passthru|popen|proc_open)\s*\(${TAINTED_ARG}`,
          ),
          label: "Shell function with interpolated/variable command (command injection)",
        },
        {
          regex: re(String.raw`\bArtisan::call\s*\(\s*${INP}`),
          label: "Artisan::call with request input (arbitrary command)",
        },
        {
          regex: re(String.raw`${FN}unserialize\s*\((?![^;]*allowed_classes['"]\s*=>\s*false)`),
          label: "unserialize without allowed_classes => false (object injection)",
        },
      ],
      content,
    );
  },
};

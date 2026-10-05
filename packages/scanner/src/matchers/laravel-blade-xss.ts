import type { MatcherPlugin } from "../types.js";
import { isLaravelSkippablePath } from "./laravel-utils.js";
import { regexMatcher } from "./utils.js";

const REQ = String.raw`(?:\$request->|request\s*\(\s*\)->)`;

/**
 * XSS and template injection in Blade views and the PHP that feeds them.
 */
export const laravelBladeXssMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "laravel-blade-xss",
  description:
    "Blade XSS / template injection — {!! !!}, HtmlString, unsafe markdown, dynamic @include/view/Blade::render",
  filePatterns: ["**/*.blade.php", "**/app/**/*.php"],
  requires: { tech: ["laravel"] },
  examples: [
    `<div>{!! $comment->body !!}</div>`,
    `@php echo $user->bio @endphp`,
    `<?= $name ?>`,
    `return new HtmlString($request->input('html'));`,
    `return new \\Illuminate\\Support\\HtmlString("<b>" . $name . "</b>");`,
    `$html = Str::markdown($post->body);`,
    `@include($template)`,
    `return view($request->input('tpl'));`,
    `return Blade::render($template, ['user' => $user]);`,
    `<script>var name = {{ $user->name }};</script>`,
    `<a href="{{ $user->website }}">site</a>`,
  ],
  match(content, filePath) {
    if (isLaravelSkippablePath(filePath)) return [];
    return regexMatcher(
      "laravel-blade-xss",
      [
        {
          regex:
            /\{!!(?!\s*(?:json_encode|Js::from|\$slot\b|\$errors|csrf_field|method_field)).*?!!\}/,
          label: "{!! !!} unescaped output (XSS if user-controlled)",
        },
        {
          regex: /@php\b.*\becho\b|<\?=\s*\$/,
          label: "Raw echo in Blade/PHP template (unescaped, XSS if user-controlled)",
        },
        {
          regex: /new\s+(?:\\Illuminate\\Support\\)?HtmlString\s*\([^)]*\$/,
          label: "HtmlString from variable (bypasses escaping)",
        },
        {
          regex: /\b(?:Str::(?:markdown|inlineMarkdown)|Markdown::parse)\s*\(/,
          label: "Markdown to HTML (informational — confirm html_input is strip/escape)",
        },
        {
          regex: /@include\s*\(\s*\$/,
          label: "@include with variable view name (template injection)",
        },
        {
          regex: new RegExp(String.raw`\b(?:view|View::make)\s*\(\s*${REQ}`),
          label: "view() name from request input (template/file disclosure)",
        },
        {
          regex: /\bBlade::render\s*\(\s*\$/,
          label: "Blade::render with variable template (RCE if user-controlled)",
        },
        {
          regex: /<script\b[^>]*>.*\{\{\s*\$/,
          label: "{{ }} inside <script> (use Js::from)",
        },
        {
          regex: /\bhref\s*=\s*["']\{\{\s*\$/,
          label: "href from variable (javascript: URL if user-controlled)",
        },
      ],
      content,
    );
  },
};

import type { MatcherPlugin } from "../types.js";
import { isLaravelSkippablePath, linesMatch, unauthorizedActions } from "./laravel-utils.js";
import { regexMatcher } from "./utils.js";

const SLUG = "laravel-livewire-filament";
// Scalar ids only: Livewire already rejects client changes to a model
// property's identity.
const IDENTITY_PROP = /^\s*public\s+(?:\??(?:int|string)\s+)?\$(?:\w*Id|id|\w*_id)\b/;
const ACTION =
  /public\s+function\s+(?:delete|update|save|destroy|remove|approve|publish|impersonate)\w*\s*\(/;
const RESOURCE = /class\s+\w+\s+extends\s+Resource\b/;
const RESOURCE_AUTH = /\bcan(?:ViewAny|View|Create|Edit|Delete)\b|\bauthorizedTo\w+/;

/**
 * Livewire/Filament/Nova: public component properties are client-writable
 * and actions are public endpoints; admin Resources default to policy
 * auto-discovery, which silently allows everything when no policy exists.
 */
export const laravelLivewireFilamentMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: SLUG,
  description:
    "Livewire/Filament/Nova — unlocked identity properties, actions without authorization, Resources without policies, ->html()/->asHtml() fields",
  filePatterns: [
    "**/app/Livewire/**/*.php",
    "**/app/Http/Livewire/**/*.php",
    "**/app/Filament/**/*.php",
    "**/app/Nova/**/*.php",
  ],
  requires: { tech: ["livewire", "nova"] },
  examples: [
    `class EditPost extends Component {\n  public int $postId;\n  public function delete() { Post::find($this->postId)->delete(); }\n}`,
    `class PostResource extends Resource { protected static ?string $model = Post::class; }`,
    `TextColumn::make('body')->html();`,
    `Text::make('Body')->asHtml(),`,
  ],
  match(content, filePath) {
    if (isLaravelSkippablePath(filePath)) return [];

    const lines = content.split("\n");
    const find = (re: RegExp, skip?: (i: number) => boolean) =>
      lines.flatMap((l, i) => (re.test(l) && !skip?.(i) ? [i + 1] : []));

    const matches = [];
    if (/extends\s+(?:\\?Livewire\\)?Component\b|\bLivewire\\/.test(content)) {
      matches.push(
        ...linesMatch(
          SLUG,
          content,
          find(
            IDENTITY_PROP,
            (i) => /#\[Locked/.test(lines[i]) || /#\[Locked/.test(lines[i - 1] ?? ""),
          ),
          "Public Livewire property is client-writable (add #[Locked] and re-authorize)",
        ),
        ...linesMatch(
          SLUG,
          content,
          unauthorizedActions(content, ACTION),
          "Livewire action with no authorization (public endpoint)",
        ),
      );
    }
    // Resource-level overrides only: every Nova field list takes a
    // `NovaRequest $request`, which isn't authorization.
    if (RESOURCE.test(content) && !RESOURCE_AUTH.test(content)) {
      matches.push(
        ...linesMatch(
          SLUG,
          content,
          find(RESOURCE),
          "Admin Resource without policy/can*() overrides (verify a policy exists)",
        ),
      );
    }
    return matches.concat(
      regexMatcher(
        SLUG,
        [
          {
            regex: /->(?:html|asHtml)\s*\(\s*\)/,
            label: "->html()/->asHtml() renders unescaped HTML (XSS)",
          },
        ],
        content,
      ),
    );
  },
};

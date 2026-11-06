import type { MatcherPlugin } from "../types.js";
import { isLaravelSkippablePath, linesMatch } from "./laravel-utils.js";
import { regexMatcher } from "./utils.js";

/**
 * Laravel misconfiguration: debug mode, hardcoded config secrets, weak
 * cookie/CORS settings, open dashboards, and CSRF/signed-URL exemptions.
 * Committed `.env` secrets are `env-exposure`'s job.
 */
export const laravelConfigExposureMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "laravel-config-exposure",
  description:
    "Laravel misconfiguration — APP_DEBUG, hardcoded config secrets, weak cookie/CORS settings, open dashboards, CSRF exemptions",
  filePatterns: [
    "**/config/*.php",
    "**/.env",
    "**/.env.*",
    "**/bootstrap/app.php",
    "**/app/Http/Middleware/*.php",
    "**/app/Providers/*ServiceProvider.php",
    "**/routes/**/*.php",
  ],
  requires: { tech: ["laravel"] },
  examples: [
    `APP_DEBUG=true`,
    `'debug' => true,`,
    `'key' => 'abcdefghijklmnop1234',`,
    `'secure' => false,`,
    `'http_only' => false,`,
    `'same_site' => 'none',`,
    `'allowed_origins' => ['*'],`,
    `'supports_credentials' => true,`,
    `Gate::define('viewTelescope', fn ($user = null) => true);`,
    `Gate::define('viewHorizon', function ($user) {`,
    `Horizon::auth(function ($request) { return true; });`,
    `->validateCsrfTokens(except: ['stripe/*']);`,
    `protected $except = ['webhook/*'];`,
    `abort_unless($request->hasValidSignature(), 403);`,
  ],
  match(content, filePath) {
    if (/\.env\.(?:example|sample|dist)$/.test(filePath) || isLaravelSkippablePath(filePath))
      return [];
    // Non-empty `$except` lists only; the stubs ship as `[ // ]`. TrimStrings
    // exempts password fields and isn't a security boundary.
    const lines = content.split("\n");
    const except = /TrimStrings\.php$/.test(filePath)
      ? []
      : lines.flatMap((l, i) =>
          /\$except\s*=\s*\[/.test(l) &&
          /\$except\s*=\s*\[\s*(?:\/\/.*\s*)*['"]/.test(lines.slice(i).join("\n"))
            ? [i + 1]
            : [],
        );
    return linesMatch(
      "laravel-config-exposure",
      content,
      except,
      "Middleware $except list (CSRF/cookie-encryption exemptions)",
    ).concat(
      regexMatcher(
        "laravel-config-exposure",
        [
          {
            regex: /^\s*APP_DEBUG\s*=\s*["']?true/i,
            label: "APP_DEBUG=true (stack traces / env leak)",
          },
          { regex: /['"]debug['"]\s*=>\s*true\b/, label: "'debug' => true hardcoded" },
          {
            regex: /['"](?:key|secret|password)['"]\s*=>\s*['"][^'"]{8,}['"]/,
            label: "Hardcoded key/secret in config",
          },
          { regex: /['"]secure['"]\s*=>\s*false\b/, label: "Session cookie 'secure' => false" },
          {
            regex: /['"]http_only['"]\s*=>\s*false\b/,
            label: "Session cookie 'http_only' => false",
          },
          {
            regex: /['"]same_site['"]\s*=>\s*(?:null|['"]none['"])/i,
            label: "Session cookie same_site null/none (CSRF exposure)",
          },
          {
            regex: /['"]allowed_origins['"]\s*=>\s*\[\s*['"]\*['"]/,
            label: "CORS allowed_origins wildcard (dangerous with supports_credentials)",
          },
          {
            regex: /['"]supports_credentials['"]\s*=>\s*true\b/,
            label: "CORS supports_credentials true (check allowed_origins)",
          },
          {
            regex:
              /Gate::define\s*\(\s*['"]view(?:Telescope|Horizon|Pulse)['"].*(?:=>|return)\s*true\b/,
            label: "Telescope/Horizon/Pulse dashboard open to everyone",
          },
          {
            regex: /\b(?:Telescope|Horizon)::auth\s*\(/,
            label: "Telescope/Horizon auth callback (confirm it is not open)",
          },
          {
            regex:
              /Gate::define\s*\(\s*['"]view(?:Telescope|Horizon|Pulse)['"](?!.*(?:=>|return)\s*true\b)/,
            label: "Dashboard gate (informational — confirm it is not open)",
          },
          {
            regex: /validateCsrfTokens\s*\(\s*except\s*:/,
            label: "validateCsrfTokens except (CSRF exemption)",
          },
          {
            regex: /->hasValid(?:Relative)?Signature(?:While)?\s*\(/,
            label: "Signed URL check (informational — confirm it guards the action)",
          },
        ],
        content,
      ),
    );
  },
};

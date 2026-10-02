import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

/**
 * Disabled TLS certificate or hostname verification (CWE-295). Each pattern
 * anchors to the explicit disable form (`false` / `0` / `disable` /
 * `skip-verify`) so verification-enabled configurations never match. Skips
 * test files across ecosystems — disabling verification against local
 * self-signed fixtures is a common, mostly-legitimate test idiom, and the
 * scan-level ignore list only pre-excludes JS-style test paths.
 */
const PATTERNS: { regex: RegExp; label: string }[] = [
  // Node / JS
  { regex: /rejectUnauthorized\s*[:=]\s*false/, label: "rejectUnauthorized: false" },
  {
    regex: /\bNODE_TLS_REJECT_UNAUTHORIZED\b\s*[=:]\s*['"]?0\b/,
    label: "NODE_TLS_REJECT_UNAUTHORIZED=0 (process-wide TLS bypass)",
  },
  { regex: /strictSSL\s*[:=]\s*false/, label: "strictSSL: false" },
  // Go
  { regex: /InsecureSkipVerify\s*:\s*true/, label: "tls.Config InsecureSkipVerify: true" },
  // Python — anchor verify=False to an HTTP-call context so it does not
  // fire on unrelated `verify=False` kwargs (jwt.decode, numpy dispatch,
  // mpmath.findroot, etc.).
  {
    regex:
      /(?:\b(?:requests|httpx|session|client|aiohttp)\b|\.(?:get|post|put|patch|delete|head|options|request|Session|Client)\s*\()[^\n]*\bverify\s*=\s*False\b/,
    label: "requests/httpx verify=False",
  },
  { regex: /ssl\._create_unverified_context/, label: "ssl._create_unverified_context" },
  { regex: /\bcheck_hostname\s*=\s*False\b/, label: "SSLContext check_hostname = False" },
  // Ruby
  { regex: /\bVERIFY_NONE\b/, label: "OpenSSL VERIFY_NONE" },
  // JVM (Apache HttpClient / HttpsURLConnection idioms)
  {
    regex:
      /\b(?:NoopHostnameVerifier|AllowAllHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|TrustAllStrategy)\b/,
    label: "permissive JVM hostname verifier / trust strategy",
  },
  // PHP
  {
    regex: /CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*(?:=>|,)\s*(?:false|0)\b/,
    label: "PHP curl SSL verification disabled",
  },
  // .NET
  {
    regex:
      /DangerousAcceptAnyServerCertificateValidator|ServerCertificate(?:Custom)?ValidationCallback\s*\+?=[^\n]*(?:=>|return)\s*true/,
    label: ".NET certificate validation callback bypassed",
  },
  // CLI tools (shell, Dockerfile, CI)
  {
    regex: /\bcurl\b[^|\n]*\s(?:--insecure\b|-[A-Za-z]*k\b)/,
    label: "curl --insecure / -k",
  },
  { regex: /\bwget\b[^\n]*--no-check-certificate/, label: "wget --no-check-certificate" },
  { regex: /http\.sslVerify\b[^\n]*\bfalse\b/i, label: "git http.sslVerify false" },
  {
    regex: /\bGIT_SSL_NO_VERIFY\b\s*=\s*['"]?(?:1|true)\b/i,
    label: "GIT_SSL_NO_VERIFY",
  },
  // Connection strings / infra config
  { regex: /\bsslmode=disable\b/, label: "connection string sslmode=disable" },
  { regex: /\btls=skip-verify\b/, label: "MySQL DSN tls=skip-verify" },
  {
    regex: /--insecure-skip-tls-verify\b|\binsecure-skip-tls-verify\s*:\s*true\b/,
    label: "kubectl/kubeconfig insecure-skip-tls-verify",
  },
];

export const tlsVerificationDisabledMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "tls-verification-disabled",
  description:
    "TLS certificate or hostname verification explicitly disabled (rejectUnauthorized:false, InsecureSkipVerify, verify=False, VERIFY_NONE, curl -k, sslmode=disable)",
  filePatterns: [
    "**/*.{ts,tsx,js,jsx,mjs,cjs}",
    "**/*.go",
    "**/*.py",
    "**/*.rb",
    "**/*.{java,kt,scala,groovy}",
    "**/*.php",
    "**/*.cs",
    "**/*.{sh,bash}",
    "**/*.{yml,yaml}",
    ".github/workflows/**/*.{yml,yaml}",
    "**/.env",
    "**/.env.*",
    "**/Dockerfile",
    "**/Dockerfile.*",
    "**/*.Dockerfile",
  ],
  examples: [
    `const agent = new https.Agent({ rejectUnauthorized: false });`,
    `process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";`,
    `NODE_TLS_REJECT_UNAUTHORIZED=0`,
    `const client = request.defaults({ strictSSL: false });`,
    `conf := &tls.Config{InsecureSkipVerify: true}`,
    `resp = requests.get(url, verify=False)`,
    `resp = httpx.get(url, verify=False)`,
    `ctx = ssl._create_unverified_context()`,
    `ctx.check_hostname = False`,
    `http.verify_mode = OpenSSL::SSL::VERIFY_NONE`,
    `.setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)`,
    `curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);`,
    `handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;`,
    `RUN curl -k https://internal.example.com/install.sh -o install.sh`,
    `curl --insecure https://internal.example.com/health`,
    `wget --no-check-certificate https://example.com/pkg.tar.gz`,
    `git config --global http.sslVerify false`,
    `GIT_SSL_NO_VERIFY=1 git clone https://git.internal/repo.git`,
    `DATABASE_URL=postgres://user:pass@db:5432/app?sslmode=disable`,
    `dsn := "user:pass@tcp(db:3306)/app?tls=skip-verify"`,
    `insecure-skip-tls-verify: true`,
    `kubectl --insecure-skip-tls-verify get pods`,
  ],
  match(content, filePath) {
    if (/_test\.go$/.test(filePath)) return [];
    if (/\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)$/.test(filePath)) return [];
    if (/(?:^|\/)__tests__\//.test(filePath)) return [];
    if (/(?:^|\/)(?:test_[^/]*|[^/]+_test)\.py$/.test(filePath)) return [];
    if (/(?:^|\/)conftest\.py$/.test(filePath)) return [];
    if (/_spec\.rb$/.test(filePath)) return [];
    if (/(?:^|\/)spec\//.test(filePath)) return [];
    if (/\.d\.ts$/.test(filePath)) return [];

    return regexMatcher("tls-verification-disabled", PATTERNS, content);
  },
};

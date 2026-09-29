import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const rsTlsNoVerifyMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "rs-tls-no-verify",
  description:
    "Rust TLS verification disabled — danger_accept_invalid_certs/hostnames, rustls dangerous_configuration, custom ServerCertVerifier, openssl SslVerifyMode::NONE",
  filePatterns: ["**/*.rs"],
  requires: { tech: ["rust"] },
  examples: [
    `let client = reqwest::Client::builder().danger_accept_invalid_certs(true).build()?;`,
    `let client = reqwest::Client::builder().danger_accept_invalid_hostnames(true).build()?;`,
    `let cfg = ClientConfig::builder().with_safe_defaults().dangerous_configuration();`,
    `impl ServerCertVerifier for NoVerify {}`,
    `impl rustls::client::ServerCertVerifier for NoVerify {}`,
    `builder.set_verify(SslVerifyMode::NONE);`,
  ],
  match(content, filePath) {
    if (/\/(tests|examples|benches)\//.test(filePath)) return [];

    return regexMatcher(
      "rs-tls-no-verify",
      [
        {
          regex: /\.danger_accept_invalid_certs\s*\(\s*true\s*\)/,
          label: "reqwest .danger_accept_invalid_certs(true)",
        },
        {
          regex: /\.danger_accept_invalid_hostnames\s*\(\s*true\s*\)/,
          label: "reqwest .danger_accept_invalid_hostnames(true)",
        },
        {
          regex: /\bdangerous_configuration\b|\bDangerousClientConfig\b/,
          label: "rustls dangerous_configuration",
        },
        {
          regex: /\bimpl\s+(?:\w+::)*ServerCertVerifier\b/,
          label: "hand-rolled ServerCertVerifier",
        },
        {
          regex: /\bSslVerifyMode::NONE\b/,
          label: "openssl SslVerifyMode::NONE",
        },
      ],
      content,
    );
  },
};

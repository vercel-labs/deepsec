import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const rsUntrustedDeserializationMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "rs-untrusted-deserialization",
  description:
    "Rust binary/streaming deserializers (bincode, rmp_serde, serde_json::from_reader, ciborium, postcard) without explicit size limits. Review for unbounded untrusted payloads — internal-trust-boundary callsites are expected false positives",
  filePatterns: ["**/*.rs"],
  requires: { tech: ["rust"] },
  examples: [
    `let value: Payload = bincode::deserialize(&bytes)?;`,
    `let (value, _): (Payload, _) = bincode::decode_from_slice(&bytes, config::standard())?;`,
    `let value: Payload = bincode::decode_from_std_read(&mut reader, config::standard())?;`,
    `let value: Payload = rmp_serde::from_slice(&bytes)?;`,
    `let value: Payload = rmp_serde::from_read(reader)?;`,
    `let value: Payload = serde_json::from_reader(reader)?;`,
    `let value: Payload = ciborium::from_reader(reader)?;`,
    `let value: Payload = postcard::from_bytes(&bytes)?;`,
  ],
  match(content, filePath) {
    if (/\/(tests|examples|benches)\//.test(filePath)) return [];

    return regexMatcher(
      "rs-untrusted-deserialization",
      [
        {
          regex: /\bbincode::deserialize\s*\(/,
          label: "bincode::deserialize",
        },
        {
          regex: /\bbincode::decode_from_slice\s*\(/,
          label: "bincode::decode_from_slice",
        },
        {
          regex: /\bbincode::decode_from_std_read\s*\(/,
          label: "bincode::decode_from_std_read",
        },
        {
          regex: /\brmp_serde::from_slice\s*\(/,
          label: "rmp_serde::from_slice",
        },
        {
          regex: /\brmp_serde::from_read\s*\(/,
          label: "rmp_serde::from_read",
        },
        {
          regex: /\bserde_json::from_reader\s*\(/,
          label: "serde_json::from_reader",
        },
        {
          regex: /\bciborium::from_reader\s*\(/,
          label: "ciborium::from_reader",
        },
        {
          regex: /\bpostcard::from_bytes\s*\(/,
          label: "postcard::from_bytes",
        },
      ],
      content,
    );
  },
};

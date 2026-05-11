import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const rsPathTraversalMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "rs-path-traversal",
  description:
    "Rust archive extraction joining untrusted entry names into a base path — zip-slip / tar-slip (CVE-2025-29787 class)",
  filePatterns: ["**/*.rs"],
  requires: { tech: ["rust"] },
  examples: [
    `let out = base.join(entry.name());`,
    `let path = dest.join(entry.path()?);`,
    `target.push(header.path()?);`,
    `for entry in archive.entries()? { let p = root.join(entry.path()?); }`,
    `let dest = output_dir.join(zip_entry.name());`,
  ],
  match(content, filePath) {
    if (/\/(tests|examples|benches)\//.test(filePath)) return [];

    return regexMatcher(
      "rs-path-traversal",
      [
        {
          regex: /\.join\s*\(\s*[^)]*\bentry\.(?:name|path)\s*\(/,
          label: "Path::join(entry.name()/path())",
        },
        {
          regex: /\.join\s*\(\s*[^)]*\bheader\.path\s*\(/,
          label: "Path::join(header.path())",
        },
        {
          regex: /\.push\s*\(\s*[^)]*\b(?:entry|header)\.(?:name|path)\s*\(/,
          label: "PathBuf::push(entry/header.path())",
        },
        {
          regex: /\.join\s*\([^)]*\b(?:zip|tar|archive)[_a-zA-Z]*\b/,
          label: ".join(...) with zip/tar/archive identifier",
        },
      ],
      content,
    );
  },
};

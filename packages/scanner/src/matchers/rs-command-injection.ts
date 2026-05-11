import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const rsCommandInjectionMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "rs-command-injection",
  description: "Rust std::process / tokio::process Command with potentially dynamic arguments",
  filePatterns: ["**/*.rs"],
  requires: { tech: ["rust"] },
  examples: [
    `let output = std::process::Command::new("ls").arg(dir).output()?;`,
    `let child = Command::new("git").arg("clone").arg(repo_url).spawn()?;`,
    `tokio::process::Command::new("sh").arg("-c").arg(user_input).status().await?;`,
    `Command::new("bash").arg("-c").arg(cmd).output()?;`,
    `let out = std::process::Command::new("pwsh").args(&args).output()?;`,
  ],
  match(content, filePath) {
    if (/\/(tests|examples|benches)\//.test(filePath)) return [];

    return regexMatcher(
      "rs-command-injection",
      [
        {
          regex: /\bstd::process::Command::new\s*\(/,
          label: "std::process::Command::new",
        },
        {
          regex: /\btokio::process::Command::new\s*\(/,
          label: "tokio::process::Command::new",
        },
        {
          regex: /\bCommand::new\s*\(\s*"(?:sh|bash|zsh|cmd|powershell|pwsh)"/,
          label: "Command::new with shell interpreter",
        },
        {
          regex: /\bCommand::new\s*\(/,
          label: "Command::new",
        },
      ],
      content,
    );
  },
};

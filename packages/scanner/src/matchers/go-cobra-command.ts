import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const goCobraCommandMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "go-cobra-command",
  description: "Cobra CLI commands — privileged-CLI surface (gated on cobra)",
  filePatterns: ["**/*.go"],
  requires: { tech: ["cobra"] },
  examples: [
    `var rootCmd = &cobra.Command{`,
    `cmd := &cobra.Command{Use: "deploy"}`,
    `	Run: func(cmd *cobra.Command, args []string) {`,
    `	RunE: func(cmd *cobra.Command, args []string) error {`,
    `	PreRun: func(cmd *cobra.Command, args []string) {`,
    `	PostRun: func(cmd *cobra.Command, args []string) {`,
    `rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file")`,
    `rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "verbose output")`,
    `rootCmd.PersistentFlags().IntVar(&port, "port", 8080, "port number")`,
    `rootCmd.AddCommand(deployCmd)`,
  ],
  match(content, filePath) {
    if (/_test\.go$/.test(filePath)) return [];

    return regexMatcher(
      "go-cobra-command",
      [
        { regex: /&cobra\.Command\s*\{/, label: "cobra.Command{} declaration" },
        {
          regex: /\b(?:Run|RunE|PreRun|PostRun)\s*:\s*func\b/,
          label: "Run/RunE handler — privileged action body",
        },
        {
          regex: /\.PersistentFlags\s*\(\s*\)\.(?:String|Bool|Int)Var/,
          label: "PersistentFlags()",
        },
        { regex: /\.AddCommand\s*\(/, label: "AddCommand registration" },
      ],
      content,
    );
  },
};

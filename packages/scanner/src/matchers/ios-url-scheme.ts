import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const iosUrlSchemeMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "ios-url-scheme",
  description: "iOS URL scheme / universal-link entry points and handlers (gated on iOS)",
  filePatterns: ["**/Info.plist", "**/*.swift", "**/*.m"],
  requires: { tech: ["ios"] },
  examples: [
    `<key>CFBundleURLSchemes</key>\n<array>\n  <string>myapp</string>\n</array>`,
    `<key>CFBundleURLSchemes</key>`,
    `<key>NSUserActivityTypes</key>\n<array><string>com.example.action</string></array>`,
    `<key>NSUserActivityTypes</key>`,
    `func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool { return true }`,
    `func application(_ application: UIApplication, open url: URL) -> Bool { return false }`,
    `func scene(_ scene: UIScene, openURLContexts URLContexts: Set<UIOpenURLContext>) {}`,
    `let webView = WKWebView(frame: .zero)`,
    `let view = UIWebView()`,
  ],
  match(content, filePath) {
    if (/\/(Tests|tests|build)\//i.test(filePath)) return [];

    return regexMatcher(
      "ios-url-scheme",
      [
        {
          regex: /<key>CFBundleURLSchemes<\/key>/,
          label: "CFBundleURLSchemes — registers URL handler",
        },
        {
          regex: /<key>NSUserActivityTypes<\/key>/,
          label: "NSUserActivityTypes — universal links",
        },
        {
          regex: /func\s+application\s*\([^)]*open\s+url\s*:\s*URL/,
          label: "application(_:open url:) — URL entry point",
        },
        {
          regex: /func\s+scene\s*\([^)]*openURLContexts\b/,
          label: "scene(_:openURLContexts:) — scene URL entry",
        },
        {
          regex: /\bWKWebView\b|\bUIWebView\b/,
          label: "WebView surface — review JS bridge / file:// loads",
        },
      ],
      content,
    );
  },
};

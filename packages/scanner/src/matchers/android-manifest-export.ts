import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const androidManifestExportMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "android-manifest-export",
  description:
    "Exported Android components (Activity / Service / Receiver / Provider) — IPC entry points (gated on android)",
  filePatterns: ["**/AndroidManifest.xml"],
  requires: { tech: ["android"] },
  examples: [
    `<activity android:name=".MainActivity" android:exported="true"/>`,
    `<service android:name=".SyncService" android:exported="true"/>`,
    `<receiver android:name=".BootReceiver" android:exported="true"/>`,
    `<provider android:name=".DataProvider" android:exported="true" android:authorities="com.example"/>`,
    `<intent-filter>\n    <action android:name="android.intent.action.VIEW"/>\n</intent-filter>`,
    `<activity android:name=".X" android:permission="com.example.PERM"/>`,
    `<service android:name=".S" android:permission="android.permission.BIND_JOB_SERVICE"/>`,
    `<data android:scheme="myapp"/>`,
    `<data android:scheme="https" android:host="example.com"/>`,
  ],
  match(content, filePath) {
    if (/\/build\//.test(filePath)) return [];

    return regexMatcher(
      "android-manifest-export",
      [
        {
          regex: /<(?:activity|service|receiver|provider)\b[^>]*android:exported="true"/,
          label: "exported component — confirm permissions",
        },
        {
          regex: /<intent-filter\b/,
          label: "intent-filter — implicitly exported on pre-31 SDK",
        },
        {
          regex: /android:permission="[^"]+"/,
          label: "android:permission= guard",
        },
        {
          regex: /<data\s+android:scheme=/,
          label: "deeplink scheme — review URL handling for SSRF/XSS",
        },
      ],
      content,
    );
  },
};

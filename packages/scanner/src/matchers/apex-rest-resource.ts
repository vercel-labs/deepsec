import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const apexRestResourceMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "apex-rest-resource",
  description: "Salesforce Apex REST resources and class sharing (gated on Apex)",
  filePatterns: ["**/*.cls"],
  requires: { tech: ["apex"] },
  examples: [
    `@RestResource(urlMapping='/Account/*')\nglobal with sharing class AccountResource {}`,
    `@RestResource(urlMapping = '/v1/users/*')\nglobal class UserResource {}`,
    `@HttpGet\nglobal static Account doGet() { return null; }`,
    `@HttpPost\nglobal static String doPost(String name) { return name; }`,
    `@HttpPut\nglobal static void doPut() {}`,
    `@HttpPatch\nglobal static void doPatch() {}`,
    `@HttpDelete\nglobal static void doDelete() {}`,
    `@HttpHead\nglobal static void doHead() {}`,
    `public without sharing class AdminOps {}`,
    `global with sharing class SafeOps {}`,
    `@AuraEnabled(cacheable=true)\npublic static List<Account> getAccounts() { return null; }`,
  ],
  match(content, filePath) {
    if (/\/(test|tests)\//i.test(filePath)) return [];

    return regexMatcher(
      "apex-rest-resource",
      [
        {
          regex: /@RestResource\s*\(\s*urlMapping\s*=\s*'[^']+'\s*\)/,
          label: "@RestResource declaration",
        },
        {
          regex: /@Http(?:Get|Post|Put|Patch|Delete|Head)\b/,
          label: "@HttpVerb method",
        },
        {
          regex: /\bwithout\s+sharing\b/,
          label: "without sharing — bypasses record-level security (REVIEW)",
        },
        { regex: /\bwith\s+sharing\b/, label: "with sharing — record security applied" },
        { regex: /\bAuraEnabled\s*\(/, label: "@AuraEnabled — exposed to Lightning" },
      ],
      content,
    );
  },
};

import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const phpDrupalControllerMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "php-drupal-controller",
  description: "Drupal controllers, routes, and form callbacks (gated on Drupal)",
  filePatterns: [
    "**/src/Controller/**/*.php",
    "**/modules/**/*.php",
    "**/modules/**/*.routing.yml",
  ],
  requires: { tech: ["drupal"] },
  examples: [
    `class UserController extends ControllerBase { public function view() {} }`,
    `class NodeListController extends ControllerBase\n{\n    public function build() { return []; }\n}`,
    `requirements:\n  _permission: 'access content'`,
    `requirements: { _permission: "access content" }`,
    `public function buildForm(array $form, FormStateInterface $form_state) { return $form; }`,
    `public function buildForm( array $form, FormStateInterface $form_state ) {}`,
    `$request = \\Drupal::request();`,
    `$ip = \\Drupal::request()->getClientIp();`,
  ],
  match(content, filePath) {
    if (/\/(tests|vendor|core\/tests)\//.test(filePath)) return [];

    return regexMatcher(
      "php-drupal-controller",
      [
        {
          regex: /class\s+\w+\s+extends\s+ControllerBase\b/,
          label: "Drupal ControllerBase subclass",
        },
        {
          regex: /_permission\s*:\s*['"]access\s+content['"]/,
          label: "permission: access content (public-ish route)",
        },
        { regex: /buildForm\s*\(\s*array\s+\$form/, label: "FormBase::buildForm() entry" },
        { regex: /\\Drupal::request\s*\(\s*\)/, label: "request() service accessor" },
      ],
      content,
    );
  },
};

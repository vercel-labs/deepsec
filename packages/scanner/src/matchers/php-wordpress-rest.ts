import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const phpWordpressRestMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "php-wordpress-rest",
  description: "WordPress REST routes, AJAX hooks, and shortcodes (gated on WordPress)",
  filePatterns: ["**/*.php"],
  requires: { tech: ["wordpress"] },
  examples: [
    `register_rest_route('myplugin/v1', '/items', ['methods' => 'GET', 'callback' => 'my_cb']);`,
    `register_rest_route( 'myplugin/v1', '/users/(?P<id>\\d+)', array( 'methods' => 'POST', 'callback' => 'cb' ) );`,
    `add_action('wp_ajax_save_settings', 'my_save_settings');`,
    `add_action("wp_ajax_nopriv_get_data", 'public_get_data');`,
    `add_shortcode('my_widget', 'render_my_widget');`,
    `add_shortcode("featured_posts", "render_featured");`,
    `register_rest_route('ns/v1', '/public', ['permission_callback' => '__return_true', 'callback' => 'cb']);`,
    `$id = $_GET['id'];`,
    `$body = $_POST;`,
    `$ua = $_SERVER['HTTP_USER_AGENT'];`,
    `$token = $_COOKIE['token'];`,
    `$val = $_REQUEST['x'];`,
  ],
  match(content, filePath) {
    if (/\/(tests|vendor|wp-includes|wp-admin)\//.test(filePath)) return [];

    return regexMatcher(
      "php-wordpress-rest",
      [
        { regex: /register_rest_route\s*\(/, label: "register_rest_route() — REST endpoint" },
        {
          regex: /add_action\s*\(\s*['"]wp_ajax_(?:nopriv_)?[^'"]+['"]/,
          label: "wp_ajax_*/wp_ajax_nopriv_* hook (nopriv = unauthenticated)",
        },
        { regex: /add_shortcode\s*\(/, label: "add_shortcode() — user-content surface" },
        {
          regex: /'permission_callback'\s*=>\s*'__return_true'/,
          label: "permission_callback => __return_true (public REST route)",
        },
        {
          regex: /\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b/,
          label: "PHP superglobal (untrusted input)",
        },
      ],
      content,
    );
  },
};

import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const phpCodeigniterControllerMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "php-codeigniter-controller",
  description: "CodeIgniter 4 controllers and route mappings (gated on CodeIgniter)",
  filePatterns: ["**/app/Controllers/**/*.php", "**/Controllers/**/*.php"],
  requires: { tech: ["codeigniter"] },
  examples: [
    `class Home extends BaseController { public function index() {} }`,
    `class Users extends ResourceController\n{\n    protected $modelName = 'App\\Models\\UserModel';\n}`,
    `class Auth extends Controller { }`,
    `$name = $this->request->getVar('name');`,
    `$body = $this->request->getPost();`,
    `$id = $this->request->getPost("id");`,
    `$routes->get('/', 'Home::index');`,
    `$routes->post("/login", 'Auth::login');`,
    `$routes->add('/x', 'X::y', ['GET', 'POST']);`,
    `helper('form');`,
    `helper("url");`,
  ],
  match(content, filePath) {
    if (/\/(tests|vendor)\//.test(filePath)) return [];

    return regexMatcher(
      "php-codeigniter-controller",
      [
        {
          regex: /class\s+\w+\s+extends\s+(?:BaseController|ResourceController|Controller)\b/,
          label: "CI Controller class",
        },
        {
          regex: /\$this->request->getVar\s*\(|\$this->request->getPost\s*\(/,
          label: "request var accessor",
        },
        {
          regex: /\$routes->(?:get|post|put|patch|delete|add)\s*\(/,
          label: "$routes-> registration",
        },
        {
          regex: /helper\s*\(\s*['"][^'"]+['"]\s*\)/,
          label: "helper() — review for unsafe loaders",
        },
      ],
      content,
    );
  },
};

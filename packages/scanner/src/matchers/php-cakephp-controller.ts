import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const phpCakephpControllerMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "php-cakephp-controller",
  description: "CakePHP controllers and component callbacks (gated on CakePHP)",
  filePatterns: ["**/src/Controller/**/*.php", "**/Controller/**/*.php"],
  requires: { tech: ["cakephp"] },
  examples: [
    `class UsersController extends AppController { }`,
    `class PostsController extends AppController\n{\n    public function index() {}\n}`,
    `$this->Auth->allow(['login', 'register']);`,
    `$this->Auth->allow();`,
    `$this->loadComponent('Auth', ['authenticate' => ['Form']]);`,
    `$this->loadComponent("Auth");`,
    `$data = $this->request->getData();`,
    `$name = $this->request->getData('name');`,
    `$this->Flash->success(__('Saved.'));`,
    `$this->Flash->error('Failed');`,
  ],
  match(content, filePath) {
    if (/\/(tests|vendor)\//.test(filePath)) return [];

    return regexMatcher(
      "php-cakephp-controller",
      [
        {
          regex: /class\s+\w+Controller\s+extends\s+AppController\b/,
          label: "CakePHP controller class",
        },
        { regex: /\$this->Auth->allow\s*\(/, label: "Auth->allow() — opens public access" },
        { regex: /\$this->loadComponent\s*\(\s*['"]Auth['"]/, label: "Auth component wiring" },
        { regex: /\$this->request->getData\s*\(/, label: "request data accessor" },
        { regex: /\$this->Flash->/, label: "flash response (post-redirect-get)" },
      ],
      content,
    );
  },
};

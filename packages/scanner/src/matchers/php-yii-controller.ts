import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const phpYiiControllerMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "php-yii-controller",
  description: "Yii2 controller classes and actionXxx methods (gated on Yii)",
  filePatterns: ["**/controllers/**/*.php", "**/src/controllers/**/*.php"],
  requires: { tech: ["yii"] },
  examples: [
    `class SiteController extends Controller { }`,
    `class UsersController extends ActiveController\n{\n    public $modelClass = 'app\\models\\User';\n}`,
    `class ApiController extends RestController { }`,
    `public function actionIndex() { return $this->render('index'); }`,
    `public function actionCreate ($id) { /* ... */ }`,
    `public function actionViewProfile() { }`,
    `public function behaviors() {\n    return [\n        'access' => ['class' => AccessControl::class],\n    ];\n}`,
    `'authenticator' => ['class' => HttpBearerAuth::class, 'except' => ContentNegotiator::class],`,
    `return ['access' => ['class' => AccessControl::class, 'rules' => []]];`,
  ],
  match(content, filePath) {
    if (/\/(tests|vendor)\//.test(filePath)) return [];

    return regexMatcher(
      "php-yii-controller",
      [
        {
          regex:
            /class\s+\w+Controller\s+extends\s+(?:Controller|ActiveController|RestController)\b/,
          label: "Yii Controller class",
        },
        {
          regex: /public\s+function\s+action[A-Z]\w*\s*\(/,
          label: "actionXxx() — Yii public action",
        },
        { regex: /\bbehaviors\s*\(\s*\)\s*[:{]/, label: "behaviors() — verify auth filter" },
        {
          regex: /AccessControl::class|ContentNegotiator::class/,
          label: "auth/behavior class wired up",
        },
      ],
      content,
    );
  },
};

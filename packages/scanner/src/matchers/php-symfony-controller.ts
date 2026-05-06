import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const phpSymfonyControllerMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "php-symfony-controller",
  description: "Symfony controllers and route attributes (gated on Symfony)",
  filePatterns: ["**/src/**/*.php", "**/src/Controller/**/*.php", "**/Controller/**/*.php"],
  requires: { tech: ["symfony"] },
  examples: [
    `#[Route('/users', name: 'users_index', methods: ['GET'])]`,
    `#[ Route("/api/items/{id}", methods: ["GET", "POST"]) ]`,
    `class UsersController extends AbstractController { }`,
    `class PostController extends AbstractController\n{\n    public function index(): Response {}\n}`,
    `#[IsGranted('ROLE_ADMIN')]`,
    `#[ IsGranted ( 'ROLE_USER' )]`,
    `#[AsEventListener(event: 'kernel.request')]`,
    `#[AsMessageHandler()]`,
    `$user = $this->getUser();`,
    `if ($this->getUser() === null) { throw new AccessDeniedException(); }`,
  ],
  match(content, filePath) {
    if (/\/(tests|vendor)\//.test(filePath)) return [];

    return regexMatcher(
      "php-symfony-controller",
      [
        { regex: /#\[\s*Route\s*\(/, label: "#[Route] attribute" },
        {
          regex: /class\s+\w+Controller\s+extends\s+AbstractController\b/,
          label: "Symfony controller class",
        },
        { regex: /#\[\s*IsGranted\s*\(/, label: "#[IsGranted] auth gate" },
        { regex: /#\[\s*AsEventListener\s*\(/, label: "Event listener entry point" },
        { regex: /#\[\s*AsMessageHandler\s*\(/, label: "Messenger handler entry point" },
        { regex: /\$this->getUser\s*\(\s*\)/, label: "auth identity accessor" },
      ],
      content,
    );
  },
};

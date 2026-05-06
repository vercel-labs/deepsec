import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const phpMagentoControllerMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "php-magento-controller",
  description: "Magento 2 controllers and webapi routes (gated on Magento)",
  filePatterns: ["**/Controller/**/*.php", "**/etc/webapi.xml"],
  requires: { tech: ["magento"] },
  examples: [
    `class Index extends \\Magento\\Framework\\App\\Action\\Action { public function execute() {} }`,
    `class View extends Magento\\Framework\\App\\Action\\Action\n{\n    public function execute() {}\n}`,
    `class Get implements \\Magento\\Framework\\App\\Action\\HttpGetActionInterface { }`,
    `class List implements Magento\\Framework\\App\\HttpGetActionInterface { }`,
    `<route url="/V1/products" method="GET">`,
    `<route url='/V1/orders/:orderId' method='POST'>`,
    `<route url="/V1/customers/me" method="PUT">`,
    `$id = $this->getRequest()->getParam('id');`,
    `$sku = $this->getRequest( )->getParam("sku");`,
  ],
  match(content, filePath) {
    if (/\/(tests|vendor|dev\/tests)\//.test(filePath)) return [];

    return regexMatcher(
      "php-magento-controller",
      [
        {
          regex: /extends\s+\\?Magento\\Framework\\App\\Action\\Action\b/,
          label: "Magento Action subclass",
        },
        {
          regex: /implements\s+\\?Magento\\Framework\\App\\(?:Action\\)?HttpGetActionInterface/,
          label: "HttpGetActionInterface implementation",
        },
        {
          regex: /<route\s+url=["'][^"']+["']\s+method=["'][A-Z]+["']/,
          label: "webapi.xml <route> declaration",
        },
        { regex: /\$this->getRequest\s*\(\s*\)->getParam\s*\(/, label: "request param accessor" },
      ],
      content,
    );
  },
};

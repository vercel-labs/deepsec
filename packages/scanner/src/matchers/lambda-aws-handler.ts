import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const lambdaAwsHandlerMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "lambda-aws-handler",
  description: "AWS Lambda handler signatures across Node/Python/Java (gated on aws-lambda)",
  filePatterns: ["**/*.{ts,js,mjs,cjs,py,java,kt}"],
  requires: { tech: ["aws-lambda"] },
  examples: [
    `exports.handler = async (event, context) => { return { statusCode: 200 } }`,
    `exports.handler = (event, context, callback) => callback(null, {})`,
    `def lambda_handler(event, context):\n    return {"statusCode": 200}`,
    `public class Handler implements RequestHandler<APIGatewayProxyEvent, APIGatewayProxyResponseEvent> {}`,
    `class MyHandler implements RequestHandler<S3Event, String> { }`,
    `import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";`,
    `const evt: APIGatewayV2Event = event;`,
    `const claims = event.requestContext.authorizer.claims;`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];
    if (/node_modules/.test(filePath)) return [];
    if (/\b(?:tests?|test)\b/i.test(filePath)) return [];

    return regexMatcher(
      "lambda-aws-handler",
      [
        {
          regex: /exports\.handler\s*=\s*(?:async\s*)?\(\s*event\b/,
          label: "Node.js exports.handler = (event, context) => ...",
        },
        {
          regex: /^\s*def\s+lambda_handler\s*\(\s*event\s*,\s*context\s*\)/m,
          label: "Python def lambda_handler(event, context)",
        },
        {
          regex: /\bimplements\s+RequestHandler<[^>]+>/,
          label: "Java RequestHandler<I,O> impl",
        },
        {
          regex: /\bAPIGateway(?:Proxy|V2)Event\b|\bAPIGatewayProxyResult\b/,
          label: "API Gateway event types",
        },
        {
          regex: /\bevent\.requestContext\.authorizer\b/,
          label: "API Gateway authorizer claim",
        },
      ],
      content,
    );
  },
};

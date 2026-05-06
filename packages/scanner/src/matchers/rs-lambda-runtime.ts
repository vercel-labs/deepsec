import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const rsLambdaRuntimeMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "rs-lambda-runtime",
  description: "Rust AWS Lambda handlers via lambda_runtime (gated on lambda-rs)",
  filePatterns: ["**/*.rs"],
  requires: { tech: ["lambda-rs"] },
  examples: [
    `lambda_runtime::run(service_fn(handler)).await?;`,
    `lambda_runtime::run( service_fn ( my_handler ) ).await?;`,
    `async fn handler(event: LambdaEvent<Request>) -> Result<Response, Error> {}`,
    `let event: LambdaEvent<ApiGatewayProxyRequest> = e;`,
    `use aws_lambda_events::event::apigw::ApiGatewayProxyRequest;`,
    `aws_lambda_events::sqs::SqsEvent`,
  ],
  match(content, filePath) {
    if (/\/(tests|examples)\//.test(filePath)) return [];

    return regexMatcher(
      "rs-lambda-runtime",
      [
        {
          regex: /\blambda_runtime::run\s*\(\s*service_fn\s*\(/,
          label: "lambda_runtime::run(service_fn(handler))",
        },
        {
          regex: /\bLambdaEvent<[^>]+>/,
          label: "LambdaEvent shape",
        },
        { regex: /\baws_lambda_events::/, label: "AWS event types (APIGatewayProxyRequest, etc.)" },
      ],
      content,
    );
  },
};

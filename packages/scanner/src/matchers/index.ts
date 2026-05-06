import { MatcherRegistry } from "../matcher-registry.js";
import { agentLoopNoCapMatcher } from "./agent-loop-no-cap.js";
import { agentToolDefinitionMatcher } from "./agent-tool-definition.js";
// --- AI / agentic / messaging matchers ---
import { agenticUntrustedPromptInputMatcher } from "./agentic-untrusted-prompt-input.js";
import { algorithmConfusionMatcher } from "./algorithm-confusion.js";
import { androidManifestExportMatcher } from "./android-manifest-export.js";
import { apexRestResourceMatcher } from "./apex-rest-resource.js";
// --- Core security matchers ---
import { authBypassMatcher } from "./auth-bypass.js";
import { azureFunctionHandlerMatcher } from "./azure-function-handler.js";
import { cacheKeyPoisoningMatcher } from "./cache-key-poisoning.js";
import { cacheKeyScopeMatcher } from "./cache-key-scope.js";
import { cljRingHandlerMatcher } from "./clj-ring-handler.js";
import { connectrpcHandlerImplMatcher } from "./connectrpc-handler-impl.js";
import { corsWildcardMatcher } from "./cors-wildcard.js";
import { crKemalRouteMatcher } from "./cr-kemal-route.js";
import { cronSecretCheckMatcher } from "./cron-secret-check.js";
// --- Finding-driven matchers ---
import { crossTenantIdMatcher } from "./cross-tenant-id.js";
import { cryptoUsageMatcher } from "./crypto-usage.js";
import { dangerousHtmlMatcher } from "./dangerous-html.js";
import { dartShelfHandlerMatcher } from "./dart-shelf-handler.js";
import { debugEndpointMatcher } from "./debug-endpoint.js";
import { devAuthBypassMatcher } from "./dev-auth-bypass.js";
import { dockerfileCurlPipeUnverifiedMatcher } from "./dockerfile-curl-pipe-unverified.js";
// --- Dockerfile / Go infra matchers ---
import { dockerfileFromMutableTagMatcher } from "./dockerfile-from-mutable-tag.js";
import { dockerfileRunAsRootMatcher } from "./dockerfile-run-as-root.js";
import { dotnetAspnetControllerMatcher } from "./dotnet-aspnet-controller.js";
import { dotnetAzureFunctionMatcher } from "./dotnet-azure-function.js";
import { dotnetMinimalApiMatcher } from "./dotnet-minimal-api.js";
import { dotnetRazorPagesMatcher } from "./dotnet-razor-pages.js";
import { dotnetSqlRawMatcher } from "./dotnet-sql-raw.js";
import { drizzleMassAssignmentMatcher } from "./drizzle-mass-assignment.js";
import { drizzleRawSqlMatcher } from "./drizzle-raw-sql.js";
import { envExposureMatcher } from "./env-exposure.js";
import { envVarAsBoolMatcher } from "./env-var-as-bool.js";
import { erlCowboyHandlerMatcher } from "./erl-cowboy-handler.js";
import { errorMessageLeakMatcher } from "./error-message-leak.js";
import { eventHandlerMismatchMatcher } from "./event-handler-mismatch.js";
import { exPhoenixControllerMatcher } from "./ex-phoenix-controller.js";
import { expensiveApiAbuseMatcher } from "./expensive-api-abuse.js";
import { fsWriteSymlinkBoundaryMatcher } from "./fs-write-symlink-boundary.js";
import { gcpCloudFunctionMatcher } from "./gcp-cloud-function.js";
import { gitProviderUrlInjectionMatcher } from "./git-provider-url-injection.js";
import { githubWorkflowSecurityMatcher } from "./github-workflow-security.js";
import { goBuffaloRouteMatcher } from "./go-buffalo-route.js";
import { goChiRouteMatcher } from "./go-chi-route.js";
import { goCobraCommandMatcher } from "./go-cobra-command.js";
import { goCommandInjectionMatcher } from "./go-command-injection.js";
import { goEchoRouteMatcher } from "./go-echo-route.js";
import { goEmbedAssetMatcher } from "./go-embed-asset.js";
import { goFiberRouteMatcher } from "./go-fiber-route.js";
import { goGinRouteMatcher } from "./go-gin-route.js";
import { goGorillaRouteMatcher } from "./go-gorilla-route.js";
import { goHttpHandlerMatcher } from "./go-http-handler.js";
import { goSqlRawMatcher } from "./go-sql-raw.js";
import { goSsrfMatcher } from "./go-ssrf.js";
// --- Authorization / IAM matchers ---
import { iamPermissionsMatcher } from "./iam-permissions.js";
import { insecureCryptoMatcher } from "./insecure-crypto.js";
import { iosUrlSchemeMatcher } from "./ios-url-scheme.js";
// --- Framework entry-point matchers (gated on detectTech) ---
import { jsAstroEndpointMatcher } from "./js-astro-endpoint.js";
import { jsBullmqProcessorMatcher } from "./js-bullmq-processor.js";
import { jsBunServeMatcher } from "./js-bun-serve.js";
import { jsDenoRouteMatcher } from "./js-deno-route.js";
import { jsExpressRouteMatcher } from "./js-express-route.js";
import { jsFastifyRouteMatcher } from "./js-fastify-route.js";
import { jsGraphqlResolverMatcher } from "./js-graphql-resolver.js";
import { jsHapiRouteMatcher } from "./js-hapi-route.js";
import { jsHonoRouteMatcher } from "./js-hono-route.js";
import { jsKoaRouteMatcher } from "./js-koa-route.js";
import { jsNestjsControllerMatcher } from "./js-nestjs-controller.js";
import { catchAllRouteAuthMatcher } from "./js-nextjs-catch-all-route-auth.js";
import { catchallRouterMatcher } from "./js-nextjs-catchall-router.js";
import { frameworkEdgeSandboxMatcher } from "./js-nextjs-edge-sandbox.js";
import { frameworkServerActionMatcher } from "./js-nextjs-fw-server-action.js";
import { frameworkImageOptimizerMatcher } from "./js-nextjs-image-optimizer.js";
import { frameworkInternalHeaderMatcher } from "./js-nextjs-internal-header.js";
import { nextjsMiddlewareMatcher } from "./js-nextjs-middleware.js";
import { nextjsMiddlewareOnlyAuthMatcher } from "./js-nextjs-middleware-only-auth.js";
// --- v3 brainstormed matchers ---
import { pageDataFetchMatcher } from "./js-nextjs-page-data-fetch.js";
import { pageWithoutAuthFetchMatcher } from "./js-nextjs-page-without-auth-fetch.js";
// --- v4 comprehensive entry point matchers ---
import { allRouteHandlersMatcher } from "./js-nextjs-route-handlers.js";
import { serverActionMatcher } from "./js-nextjs-server-action.js";
import { serverActionNoAuthMatcher } from "./js-nextjs-server-action-no-auth.js";
import { allServerActionsMatcher } from "./js-nextjs-server-actions.js";
// --- Framework (Next.js) matchers ---
import { frameworkUntrustedFetchMatcher } from "./js-nextjs-untrusted-fetch.js";
import { useServerExportMatcher } from "./js-nextjs-use-server-export.js";
import { jsNosqlInjectionMatcher } from "./js-nosql-injection.js";
import { jsNuxtRouteMatcher } from "./js-nuxt-route.js";
import { unsafeJsonInHtmlMatcher } from "./js-react-unsafe-json-in-html.js";
import { jsRemixRouteMatcher } from "./js-remix-route.js";
import { jsSocketioHandlerMatcher } from "./js-socketio-handler.js";
import { jsSolidstartActionMatcher } from "./js-solidstart-action.js";
import { jsSqlRawMatcher } from "./js-sql-raw.js";
import { jsSveltekitRouteMatcher } from "./js-sveltekit-route.js";
import { jsWorkersFetchMatcher } from "./js-workers-fetch.js";
import { jvmJaxrsResourceMatcher } from "./jvm-jaxrs-resource.js";
import { jvmKtorRouteMatcher } from "./jvm-ktor-route.js";
import { jvmMicronautControllerMatcher } from "./jvm-micronaut-controller.js";
import { jvmSpringControllerMatcher } from "./jvm-spring-controller.js";
import { jvmSqlRawMatcher } from "./jvm-sql-raw.js";
// --- Auth / sessions / env matchers ---
import { jwtHandlingMatcher } from "./jwt-handling.js";
import { k8sSecretReferenceMatcher } from "./k8s-secret-reference.js";
import { k8sSecretsInitContainerMatcher } from "./k8s-secrets-init-container.js";
import { lambdaAwsHandlerMatcher } from "./lambda-aws-handler.js";
import { luaCryptoWeaknessMatcher } from "./lua-crypto-weakness.js";
import { luaNgxExecMatcher } from "./lua-ngx-exec.js";
import { luaRegexBypassMatcher } from "./lua-regex-bypass.js";
import { luaSharedDictPoisoningMatcher } from "./lua-shared-dict-poisoning.js";
// --- Lua / Go / proxy matchers ---
import { luaStringConcatUrlMatcher } from "./lua-string-concat-url.js";
import { mcpToolHandlerMatcher } from "./mcp-tool-handler.js";
import { missingAuthMatcher } from "./missing-auth.js";
import { missingAwaitMatcher } from "./missing-await.js";
import { nonAtomicOperationMatcher } from "./non-atomic-operation.js";
import { nonAtomicReadDeleteMatcher } from "./non-atomic-read-delete.js";
import { oauthFlowMatcher } from "./oauth-flow.js";
import { objectInjectionMatcher } from "./object-injection.js";
import { openRedirectMatcher } from "./open-redirect.js";
import { pathTraversalMatcher } from "./path-traversal.js";
import { phpCakephpControllerMatcher } from "./php-cakephp-controller.js";
import { phpCodeigniterControllerMatcher } from "./php-codeigniter-controller.js";
import { phpDrupalControllerMatcher } from "./php-drupal-controller.js";
import { phpLaravelRouteMatcher } from "./php-laravel-route.js";
import { phpMagentoControllerMatcher } from "./php-magento-controller.js";
import { phpSlimRouteMatcher } from "./php-slim-route.js";
import { phpSqlRawMatcher } from "./php-sql-raw.js";
import { phpSymfonyControllerMatcher } from "./php-symfony-controller.js";
import { phpWordpressRestMatcher } from "./php-wordpress-rest.js";
import { phpYiiControllerMatcher } from "./php-yii-controller.js";
import { postmessageOriginMatcher } from "./postmessage-origin.js";
import { prismaRawSqlMatcher } from "./prisma-raw-sql.js";
import { processEnvAccessMatcher } from "./process-env-access.js";
import { promptLeaksSystemPromptMatcher } from "./prompt-leaks-system-prompt.js";
// --- ConnectRPC / proto / Unix-socket matchers ---
import { protoRpcSurfaceMatcher } from "./proto-rpc-surface.js";
// --- Endpoint / handler matchers ---
import { publicEndpointMatcher } from "./public-endpoint.js";
import { pyAiohttpRouteMatcher } from "./py-aiohttp-route.js";
import { pyAirflowDagMatcher } from "./py-airflow-dag.js";
import { pyBottleRouteMatcher } from "./py-bottle-route.js";
import { pyCeleryTaskMatcher } from "./py-celery-task.js";
import { pyDjangoViewMatcher } from "./py-django-view.js";
import { pyFalconResourceMatcher } from "./py-falcon-resource.js";
import { pyFastapiRouteMatcher } from "./py-fastapi-route.js";
import { pyFlaskRouteMatcher } from "./py-flask-route.js";
import { pyNosqlInjectionMatcher } from "./py-nosql-injection.js";
import { pySanicRouteMatcher } from "./py-sanic-route.js";
import { pySqlRawMatcher } from "./py-sql-raw.js";
import { pyStarletteRouteMatcher } from "./py-starlette-route.js";
import { pyTornadoHandlerMatcher } from "./py-tornado-handler.js";
import { rateLimitBypassMatcher } from "./rate-limit-bypass.js";
import { rbGrapeEndpointMatcher } from "./rb-grape-endpoint.js";
import { rbHanamiActionMatcher } from "./rb-hanami-action.js";
import { rbRailsControllerMatcher } from "./rb-rails-controller.js";
import { rbRodaRouteMatcher } from "./rb-roda-route.js";
import { rbSinatraRouteMatcher } from "./rb-sinatra-route.js";
import { rbSqlRawMatcher } from "./rb-sql-raw.js";
import { rceMatcher } from "./rce.js";
import { responseHeaderLeakMatcher } from "./response-header-leak.js";
import { rsActixRouteMatcher } from "./rs-actix-route.js";
import { rsAxumRouteMatcher } from "./rs-axum-route.js";
import { rsLambdaRuntimeMatcher } from "./rs-lambda-runtime.js";
import { rsPoemRouteMatcher } from "./rs-poem-route.js";
import { rsRocketRouteMatcher } from "./rs-rocket-route.js";
import { rsSqlRawMatcher } from "./rs-sql-raw.js";
import { rsTideRouteMatcher } from "./rs-tide-route.js";
import { rsTonicGrpcMatcher } from "./rs-tonic-grpc.js";
import { rsWarpFilterMatcher } from "./rs-warp-filter.js";
import { sandboxRuntimeScriptMatcher } from "./sandbox-runtime-script.js";
import { secretEnvVarMatcher } from "./secret-env-var.js";
import { secretInFallbackMatcher } from "./secret-in-fallback.js";
import { secretInLogMatcher } from "./secret-in-log.js";
import { secretsExposureMatcher } from "./secrets-exposure.js";
// --- Secrets management matchers ---
import { secretsPlaintextExposureMatcher } from "./secrets-plaintext-exposure.js";
import { securityBehindFlagMatcher } from "./security-behind-flag.js";
import { sensitiveDataInTracesMatcher } from "./sensitive-data-in-traces.js";
import { serviceEntryPointMatcher } from "./service-entry-point.js";
import { sessionCookieConfigMatcher } from "./session-cookie-config.js";
import { slackSigningVerificationMatcher } from "./slack-signing-verification.js";
import { snowflakeBigquerySqlMatcher } from "./snowflake-bigquery-sql.js";
import { soqlInjectionMatcher } from "./soql-injection.js";
import { spreadOperatorInjectionMatcher } from "./spread-operator-injection.js";
import { sqlInjectionMatcher } from "./sql-injection.js";
import { ssrfMatcher } from "./ssrf.js";
import { streamingEndpointMatcher } from "./streaming-endpoint.js";
import { swiftVaporRouteMatcher } from "./swift-vapor-route.js";
import { testHeaderBypassMatcher } from "./test-header-bypass.js";
import { tfEncryptionMissingMatcher } from "./tf-encryption-missing.js";
import { tfIacSurfaceMatcher } from "./tf-iac-surface.js";
// --- Terraform / IaC matchers ---
import { tfIamWildcardMatcher } from "./tf-iam-wildcard.js";
import { tfModuleUnpinnedMatcher } from "./tf-module-unpinned.js";
import { tfPublicIngressMatcher } from "./tf-public-ingress.js";
import { tfSecretInDataMatcher } from "./tf-secret-in-data.js";
import { trpcPublicProcedureMatcher } from "./trpc-public-procedure.js";
import { unixSocketListenerMatcher } from "./unix-socket-listener.js";
import { unsafeDeserializationMatcher } from "./unsafe-deserialization.js";
import { unsafeRedirectMatcher } from "./unsafe-redirect.js";
import { untrustedRedirectFollowingMatcher } from "./untrusted-redirect-following.js";
// --- v2 finding-driven matchers ---
import { unverifiedLookupMatcher } from "./unverified-lookup.js";
import { urlRegexValidationMatcher } from "./url-regex-validation.js";
import { webhookHandlerMatcher } from "./webhook-handler.js";
import { xssMatcher } from "./xss.js";
import { zodPassthroughMassAssignmentMatcher } from "./zod-passthrough-mass-assignment.js";

export function createDefaultRegistry(): MatcherRegistry {
  const registry = new MatcherRegistry();

  // Core security
  registry.register(authBypassMatcher);
  registry.register(missingAuthMatcher);
  registry.register(xssMatcher);
  registry.register(rceMatcher);
  registry.register(sqlInjectionMatcher);
  registry.register(ssrfMatcher);
  registry.register(pathTraversalMatcher);
  registry.register(secretsExposureMatcher);
  registry.register(insecureCryptoMatcher);
  registry.register(openRedirectMatcher);

  // Endpoint / handler
  registry.register(publicEndpointMatcher);
  registry.register(serviceEntryPointMatcher);
  registry.register(webhookHandlerMatcher);

  // Authorization / IAM
  registry.register(iamPermissionsMatcher);
  registry.register(serverActionMatcher);
  registry.register(unsafeRedirectMatcher);
  registry.register(dangerousHtmlMatcher);

  // Auth / sessions / env
  registry.register(jwtHandlingMatcher);
  registry.register(envExposureMatcher);
  registry.register(rateLimitBypassMatcher);

  // Finding-driven
  registry.register(crossTenantIdMatcher);
  registry.register(secretInFallbackMatcher);
  registry.register(secretInLogMatcher);
  registry.register(urlRegexValidationMatcher);
  registry.register(gitProviderUrlInjectionMatcher);
  registry.register(cronSecretCheckMatcher);
  registry.register(useServerExportMatcher);
  registry.register(nextjsMiddlewareOnlyAuthMatcher);

  // Lua / Go / proxy
  registry.register(luaStringConcatUrlMatcher);
  registry.register(luaNgxExecMatcher);
  registry.register(luaSharedDictPoisoningMatcher);
  registry.register(luaRegexBypassMatcher);
  registry.register(luaCryptoWeaknessMatcher);
  registry.register(goHttpHandlerMatcher);
  registry.register(goSsrfMatcher);
  registry.register(goCommandInjectionMatcher);
  registry.register(cacheKeyPoisoningMatcher);
  registry.register(secretEnvVarMatcher);

  // v2 finding-driven
  registry.register(unverifiedLookupMatcher);
  registry.register(catchAllRouteAuthMatcher);
  registry.register(serverActionNoAuthMatcher);
  registry.register(oauthFlowMatcher);
  registry.register(securityBehindFlagMatcher);

  // v3 brainstormed
  registry.register(pageDataFetchMatcher);
  registry.register(spreadOperatorInjectionMatcher);
  registry.register(nonAtomicOperationMatcher);
  registry.register(debugEndpointMatcher);
  registry.register(postmessageOriginMatcher);
  registry.register(algorithmConfusionMatcher);
  registry.register(objectInjectionMatcher);
  registry.register(envVarAsBoolMatcher);
  registry.register(responseHeaderLeakMatcher);
  registry.register(corsWildcardMatcher);
  registry.register(unsafeDeserializationMatcher);
  registry.register(pageWithoutAuthFetchMatcher);
  registry.register(unsafeJsonInHtmlMatcher);

  // v4 comprehensive entry point
  registry.register(allRouteHandlersMatcher);
  registry.register(allServerActionsMatcher);
  registry.register(nextjsMiddlewareMatcher);
  registry.register(catchallRouterMatcher);
  registry.register(agentToolDefinitionMatcher);
  registry.register(devAuthBypassMatcher);
  registry.register(streamingEndpointMatcher);
  registry.register(expensiveApiAbuseMatcher);
  registry.register(processEnvAccessMatcher);
  registry.register(missingAwaitMatcher);
  registry.register(sensitiveDataInTracesMatcher);
  registry.register(cacheKeyScopeMatcher);
  registry.register(nonAtomicReadDeleteMatcher);
  registry.register(testHeaderBypassMatcher);
  registry.register(eventHandlerMismatchMatcher);
  registry.register(errorMessageLeakMatcher);

  // Dockerfile / Go infra
  registry.register(dockerfileFromMutableTagMatcher);
  registry.register(dockerfileCurlPipeUnverifiedMatcher);
  registry.register(dockerfileRunAsRootMatcher);
  registry.register(cryptoUsageMatcher);

  // Secrets management
  registry.register(secretsPlaintextExposureMatcher);
  registry.register(k8sSecretReferenceMatcher);
  registry.register(k8sSecretsInitContainerMatcher);

  // ConnectRPC / proto / Unix-socket
  registry.register(protoRpcSurfaceMatcher);
  registry.register(connectrpcHandlerImplMatcher);
  registry.register(unixSocketListenerMatcher);
  registry.register(sandboxRuntimeScriptMatcher);
  registry.register(goEmbedAssetMatcher);
  registry.register(githubWorkflowSecurityMatcher);

  // Terraform / IaC
  registry.register(tfIamWildcardMatcher);
  registry.register(tfPublicIngressMatcher);
  registry.register(tfEncryptionMissingMatcher);
  registry.register(tfSecretInDataMatcher);
  registry.register(tfModuleUnpinnedMatcher);
  registry.register(tfIacSurfaceMatcher);

  // Framework (Next.js)
  registry.register(frameworkUntrustedFetchMatcher);
  registry.register(frameworkInternalHeaderMatcher);
  registry.register(frameworkServerActionMatcher);
  registry.register(frameworkImageOptimizerMatcher);
  registry.register(frameworkEdgeSandboxMatcher);

  // AI / agentic / messaging
  registry.register(agenticUntrustedPromptInputMatcher);
  registry.register(drizzleRawSqlMatcher);
  registry.register(soqlInjectionMatcher);
  registry.register(snowflakeBigquerySqlMatcher);
  registry.register(mcpToolHandlerMatcher);
  registry.register(slackSigningVerificationMatcher);
  registry.register(drizzleMassAssignmentMatcher);
  registry.register(sessionCookieConfigMatcher);
  registry.register(zodPassthroughMassAssignmentMatcher);
  registry.register(untrustedRedirectFollowingMatcher);
  registry.register(agentLoopNoCapMatcher);
  registry.register(promptLeaksSystemPromptMatcher);
  registry.register(fsWriteSymlinkBoundaryMatcher);
  registry.register(prismaRawSqlMatcher);
  registry.register(trpcPublicProcedureMatcher);

  // Framework entry-point matchers — each gated on a `detectTech` tag so
  // they stay dormant on repos that don't use the framework. Grouped by
  // ecosystem for readability.
  // Node / TS / JS
  registry.register(jsExpressRouteMatcher);
  registry.register(jsFastifyRouteMatcher);
  registry.register(jsNestjsControllerMatcher);
  registry.register(jsHonoRouteMatcher);
  registry.register(jsKoaRouteMatcher);
  registry.register(jsHapiRouteMatcher);
  registry.register(jsRemixRouteMatcher);
  registry.register(jsSveltekitRouteMatcher);
  registry.register(jsNuxtRouteMatcher);
  registry.register(jsAstroEndpointMatcher);
  registry.register(jsSolidstartActionMatcher);
  registry.register(jsGraphqlResolverMatcher);
  registry.register(jsSocketioHandlerMatcher);
  registry.register(jsBullmqProcessorMatcher);
  registry.register(jsBunServeMatcher);
  registry.register(jsDenoRouteMatcher);
  registry.register(jsWorkersFetchMatcher);
  // PHP
  registry.register(phpLaravelRouteMatcher);
  registry.register(phpSymfonyControllerMatcher);
  registry.register(phpSlimRouteMatcher);
  registry.register(phpYiiControllerMatcher);
  registry.register(phpCakephpControllerMatcher);
  registry.register(phpCodeigniterControllerMatcher);
  registry.register(phpWordpressRestMatcher);
  registry.register(phpDrupalControllerMatcher);
  registry.register(phpMagentoControllerMatcher);
  // Python
  registry.register(pyDjangoViewMatcher);
  registry.register(pyFastapiRouteMatcher);
  registry.register(pyFlaskRouteMatcher);
  registry.register(pyStarletteRouteMatcher);
  registry.register(pyAiohttpRouteMatcher);
  registry.register(pyTornadoHandlerMatcher);
  registry.register(pySanicRouteMatcher);
  registry.register(pyBottleRouteMatcher);
  registry.register(pyFalconResourceMatcher);
  registry.register(pyCeleryTaskMatcher);
  registry.register(pyAirflowDagMatcher);
  // Ruby
  registry.register(rbRailsControllerMatcher);
  registry.register(rbSinatraRouteMatcher);
  registry.register(rbGrapeEndpointMatcher);
  registry.register(rbHanamiActionMatcher);
  registry.register(rbRodaRouteMatcher);
  // Go
  registry.register(goGinRouteMatcher);
  registry.register(goEchoRouteMatcher);
  registry.register(goFiberRouteMatcher);
  registry.register(goChiRouteMatcher);
  registry.register(goGorillaRouteMatcher);
  registry.register(goBuffaloRouteMatcher);
  registry.register(goCobraCommandMatcher);
  // Rust
  registry.register(rsActixRouteMatcher);
  registry.register(rsAxumRouteMatcher);
  registry.register(rsRocketRouteMatcher);
  registry.register(rsWarpFilterMatcher);
  registry.register(rsTideRouteMatcher);
  registry.register(rsPoemRouteMatcher);
  registry.register(rsTonicGrpcMatcher);
  registry.register(rsLambdaRuntimeMatcher);
  // JVM
  registry.register(jvmSpringControllerMatcher);
  registry.register(jvmKtorRouteMatcher);
  registry.register(jvmMicronautControllerMatcher);
  registry.register(jvmJaxrsResourceMatcher);
  // .NET
  registry.register(dotnetAspnetControllerMatcher);
  registry.register(dotnetMinimalApiMatcher);
  registry.register(dotnetRazorPagesMatcher);
  registry.register(dotnetAzureFunctionMatcher);
  // Other ecosystems
  registry.register(exPhoenixControllerMatcher);
  registry.register(crKemalRouteMatcher);
  registry.register(cljRingHandlerMatcher);
  registry.register(erlCowboyHandlerMatcher);
  registry.register(swiftVaporRouteMatcher);
  registry.register(dartShelfHandlerMatcher);
  registry.register(apexRestResourceMatcher);
  // Cloud function platforms
  registry.register(lambdaAwsHandlerMatcher);
  registry.register(gcpCloudFunctionMatcher);
  registry.register(azureFunctionHandlerMatcher);
  // Mobile
  registry.register(androidManifestExportMatcher);
  registry.register(iosUrlSchemeMatcher);

  // Raw-SQL escape hatches across language ecosystems — each gated on
  // the language tag so they stay dormant on unrelated repos. Driver-
  // specific patterns (TypeORM, JDBC, Dapper, …) are bundled inside
  // each ecosystem matcher rather than spread across one-file-per-ORM.
  registry.register(jsSqlRawMatcher);
  registry.register(jsNosqlInjectionMatcher);
  registry.register(pySqlRawMatcher);
  registry.register(pyNosqlInjectionMatcher);
  registry.register(jvmSqlRawMatcher);
  registry.register(phpSqlRawMatcher);
  registry.register(rbSqlRawMatcher);
  registry.register(goSqlRawMatcher);
  registry.register(rsSqlRawMatcher);
  registry.register(dotnetSqlRawMatcher);

  return registry;
}

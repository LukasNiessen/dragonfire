import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { StageResolver } from "../packages/stages/src/index.js";
import { RepositoryIngestor } from "../packages/ingest/src/index.js";
import { BUILTIN_MATCHERS, SECURITY_SURFACE_SEEDS, MatcherEngine } from "../packages/scanner/src/index.js";
import { RevalidationRunner, ReviewRunner } from "../packages/orchestrator/src/index.js";
import { DEFAULT_CONFIG } from "../packages/core/src/index.js";
import { copyFixture, makeTempProject } from "../packages/testkit/src/index.js";
import { PackManager } from "../packages/marketplace/src/index.js";
import {
  AgentExecutionError,
  AgenticRepositoryInvestigatorAgent,
  ModelBackedInvestigatorAgent,
  PromptCompiler,
  type ModelGateway
} from "../packages/agents/src/index.js";
import { buildControlReport } from "../packages/standards/src/index.js";
import {
  buildCatalogSummary,
  buildExportBundle,
  buildStatusSummary,
  changedFilesSinceLastRun,
  computeMetrics,
  explainFinding,
  triageFindings
} from "../packages/cli/src/index.js";
import { createDefaultExternalToolRegistry, runCommand } from "../packages/tools/src/index.js";
import { CommandSandboxPolicy } from "../packages/tools/src/sandbox.js";
import { ExtensionRegistry, type NotificationRecord } from "../packages/extensions/src/index.js";
import { runPreflight } from "../packages/preflight/src/index.js";
import { regexMatcher } from "../packages/scanner/src/index.js";

const repoRoot = process.cwd();
const fixtureRoot = path.join(repoRoot, "fixtures", "vulnerable-webapp");

const tests: Array<[string, () => Promise<void>]> = [
  ["StageResolver infers pull_request and applies preset", async () => {
    const plan = new StageResolver().resolve({
      event: { type: "pull_request" },
      config: { ...DEFAULT_CONFIG, projectId: "demo", defaultStage: "dev", stages: {} },
      cliOverrides: {}
    });
    assert.equal(plan.name, "pull_request");
    assert.equal(plan.matcherProfile, "strict");
    assert.equal(plan.graphRadius, 1);
  }],
  ["StageResolver allows CLI stage override", async () => {
    const plan = new StageResolver().resolve({
      event: { type: "pull_request" },
      config: { ...DEFAULT_CONFIG, projectId: "demo", defaultStage: "pull_request", stages: {} },
      cliOverrides: { stage: "stage" }
    });
    assert.equal(plan.name, "stage");
    assert.equal(plan.matcherProfile, "balanced");
  }],
  ["MatcherEngine emits deterministic signals for vulnerable fixture", async () => {
    const snapshot = await new RepositoryIngestor().ingest({
      rootPath: fixtureRoot,
      runId: "test_run",
      projectId: "fixture",
      stagePlan: new StageResolver().resolve({
        config: { ...DEFAULT_CONFIG, projectId: "fixture" },
        cliOverrides: { stage: "stage" }
      }),
      explicitFiles: ["src/api/users.ts", "src/api/admin.ts", "src/api/webhook.ts"]
    });
    const signals = await new MatcherEngine().run({
      snapshot,
      stagePlan: { matcherProfile: "balanced" }
    });
    const slugs = signals.map((signal) => signal.slug);
    assert.ok(slugs.includes("sql-injection"));
    assert.ok(slugs.includes("missing-auth"));
    assert.ok(slugs.includes("webhook-no-signature"));
  }],
  ["Built-in matcher catalog is broad enough for MVP release", async () => {
    const slugs = new Set(BUILTIN_MATCHERS.map((matcher) => matcher.slug));
    assert.ok(BUILTIN_MATCHERS.length >= 430, `expected at least 430 built-in matchers, got ${BUILTIN_MATCHERS.length}`);
    assert.equal(slugs.size, BUILTIN_MATCHERS.length, "built-in matcher slugs must be unique");
    const missingSecuritySeeds = SECURITY_SURFACE_SEEDS.filter((slug) => !slugs.has(slug));
    assert.deepEqual(missingSecuritySeeds, [], "Proofstrike must include every built-in security surface seed");
    const seedWithoutExamples = SECURITY_SURFACE_SEEDS.filter((slug) => {
      const matcher = BUILTIN_MATCHERS.find((item) => item.slug === slug);
      return !matcher?.examples?.length;
    });
    assert.deepEqual(seedWithoutExamples, [], "Every security surface seed must carry at least one inline example");
    for (const slug of [
      "tenant-id-from-request",
      "jwt-decode-without-verify",
      "public-admin-route",
      "mcp-tool-handler",
      "github-pull-request-target",
      "terraform-public-ingress",
      "dockerfile-curl-pipe",
      "secret-github-token",
      "express-session-default-secret",
      "python-yaml-unsafe-load",
      "prisma-query-raw-unsafe",
      "ai-tool-shell-access",
      "github-actions-permissions-write-all",
      "terraform-rds-public",
      "k8s-host-network",
      "dockerfile-ssh-key-copy",
      "android-cleartext-traffic",
      "electron-node-integration",
      "surface-express-http-entrypoint",
      "surface-go-gin-route",
      "surface-rust-axum-route",
      "surface-php-laravel-route",
      "surface-jvm-spring-controller",
      "surface-dotnet-minimal-api",
      "surface-swift-vapor-route",
      "surface-apex-rest-resource",
      "surface-cache-poisoning-vector",
      "surface-terraform-public-ingress",
      "surface-web-postmessage-origin"
    ]) {
      assert.ok(slugs.has(slug), `missing matcher ${slug}`);
    }
  }],
  ["Expanded matcher catalog detects representative polyglot and CI/IaC issues", async () => {
    const temp = makeTempProject("proofstrike-expanded-matchers");
    const write = (relPath: string, content: string) => {
      const target = path.join(temp, relPath);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, content, "utf8");
    };
    write("package.json", "{\"dependencies\":{\"express\":\"latest\",\"jsonwebtoken\":\"latest\"}}\n");
    write("src/app.ts", [
      "import { exec } from 'node:child_process';",
      "app.use(session({ secret: 'keyboard cat', cookie: { secure: false, httpOnly: false } }));",
      "jwt.verify(token, secret, { ignoreExpiration: true });",
      "exec(req.query.cmd as string);",
      "const sql = prisma.$queryRawUnsafe(req.body.query);",
      "const rendered = dangerouslySetInnerHTML({ __html: modelResponse });"
    ].join("\n"));
    write("ai/tool.ts", [
      "server.tool('shell', { handler: ({ command }) => exec(command) });",
      "const args = JSON.parse(toolCall.arguments);",
      "memory.store('token', user.token);"
    ].join("\n"));
    write(".github/workflows/pr.yml", [
      "on: [pull_request]",
      "permissions: write-all",
      "jobs:",
      "  build:",
      "    runs-on: [self-hosted, linux]",
      "    steps:",
      "      - run: echo ${{ secrets.PROD_TOKEN }}"
    ].join("\n"));
    write("infra/main.tf", [
      "resource \"aws_db_instance\" \"db\" {",
      "  publicly_accessible = true",
      "  storage_encrypted = false",
      "}",
      "resource \"aws_instance\" \"web\" { metadata_options { http_tokens = \"optional\" } }",
      "resource \"aws_lambda_function\" \"fn\" {",
      "  environment { variables = { API_KEY = \"hardcoded-secret\" } }",
      "}"
    ].join("\n"));
    write("k8s/deploy.yaml", [
      "apiVersion: apps/v1",
      "kind: Deployment",
      "spec:",
      "  template:",
      "    spec:",
      "      hostNetwork: true",
      "      containers:",
      "        - name: app",
      "          image: example/app:latest",
      "          securityContext:",
      "            allowPrivilegeEscalation: true",
      "---",
      "kind: Service",
      "spec:",
      "  type: LoadBalancer"
    ].join("\n"));
    write("Dockerfile", [
      "FROM node:latest",
      "ARG API_KEY=hardcoded-secret",
      "COPY id_rsa /root/.ssh/id_rsa"
    ].join("\n"));
    write("mobile/AndroidManifest.xml", "<manifest><application android:allowBackup=\"true\" android:usesCleartextTraffic=\"true\" /></manifest>");
    write("mobile/Info.plist", "<plist><dict><key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/></dict></dict></plist>");
    write("Cargo.toml", "[dependencies]\nfoo = { git = \"https://github.com/example/foo\" }\n");
    write("build.gradle", "implementation 'org.foo:bar:1.+'\n");
    write("Jenkinsfile", "pipeline { stages { stage('deploy') { steps { sh \"deploy ${params.ENV}\" } } } }\n");

    const stagePlan = new StageResolver().resolve({
      config: { ...DEFAULT_CONFIG, projectId: "expanded", defaultStage: "campaign", stages: {} },
      cliOverrides: { stage: "campaign" }
    });
    const snapshot = await new RepositoryIngestor().ingest({
      rootPath: temp,
      runId: "expanded_run",
      projectId: "expanded",
      stagePlan
    });
    const scopedPaths = new Set(snapshot.files.map((file) => file.filePath));
    for (const relPath of ["mobile/AndroidManifest.xml", "mobile/Info.plist", "Cargo.toml", "build.gradle", "Jenkinsfile"]) {
      assert.ok(scopedPaths.has(relPath), `ingestor should include ${relPath}`);
    }

    const signals = await new MatcherEngine().run({ snapshot, stagePlan });
    const signalSlugs = new Set(signals.map((signal) => signal.slug));
    const expected = [
      "express-session-default-secret",
      "session-cookie-secure-false",
      "session-cookie-http-only-false",
      "jwt-ignore-expiration",
      "node-child-process-user-input",
      "prisma-query-raw-unsafe",
      "ai-tool-shell-access",
      "function-calling-arguments-unvalidated",
      "agent-memory-stores-secrets",
      "github-actions-permissions-write-all",
      "github-actions-self-hosted-pr",
      "github-actions-env-secret-echo",
      "terraform-rds-public",
      "terraform-rds-no-encryption",
      "terraform-imds-v1",
      "terraform-lambda-env-secret",
      "k8s-host-network",
      "k8s-allow-privilege-escalation",
      "k8s-image-latest",
      "k8s-service-loadbalancer-public",
      "dockerfile-latest-tag",
      "dockerfile-secret-arg",
      "dockerfile-ssh-key-copy",
      "android-allow-backup-true",
      "android-cleartext-traffic",
      "ios-app-transport-security-disabled",
      "cargo-git-unpinned",
      "gradle-dynamic-version",
      "jenkins-shell-user-param"
    ];
    const missing = expected.filter((slug) => !signalSlugs.has(slug));
    assert.deepEqual(missing, []);
  }],
  ["Framework specialist scanner detects targeted framework failure modes", async () => {
    const temp = makeTempProject("proofstrike-framework-specialists");
    const write = (relPath: string, content: string) => {
      const target = path.join(temp, relPath);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, content, "utf8");
    };
    write("package.json", JSON.stringify({
      dependencies: {
        next: "latest",
        express: "latest",
        fastify: "latest",
        "@nestjs/core": "latest",
        "@trpc/server": "latest",
        graphql: "latest",
        electron: "latest"
      }
    }));
    write("app/users/actions.ts", [
      "'use server';",
      "export async function updateUser(formData: FormData) {",
      "  return db.user.update({ data: Object.fromEntries(formData) });",
      "}"
    ].join("\n"));
    write("app/login/route.ts", "export function GET(req) { return NextResponse.redirect(req.nextUrl.searchParams.get('next')); }\n");
    write("src/express.ts", [
      "router.post('/admin/users', async (req, res) => res.json(await updateUser(req.body)));",
      "router.post('/stripe/webhook', express.json(), async (req, res) => res.json(await handle(req.body)));"
    ].join("\n"));
    write("src/fastify.ts", "fastify.post('/orders', async (request) => saveOrder(request.body));\n");
    write("src/admin.controller.ts", "@Controller('admin') export class Admin { @Post() update(@Body() body) { return save(body); } }\n");
    write("src/router.ts", "export const r = router({ update: publicProcedure.mutation(({ input, ctx }) => ctx.db.user.update(input)) });\n");
    write("src/graphql.ts", "export const resolvers = { Mutation: { updateUser: (_, args) => db.user.update(args.input) } };\n");
    write("python/views.py", [
      "from django.views.decorators.csrf import csrf_exempt",
      "@csrf_exempt",
      "def update(request):",
      "    cursor.execute(f\"select * from users where id = {request.GET['id']}\")",
      "    return ok()",
      "app = FastAPI()",
      "@app.post('/admin')",
      "def admin(payload: dict = Body(...)):",
      "    return payload"
    ].join("\n"));
    write("app/controllers/users_controller.rb", [
      "class UsersController < ApplicationController",
      "  skip_before_action :authenticate_user!",
      "  def update; User.update(params[:user]); end",
      "end"
    ].join("\n"));
    write("src/main/resources/application.properties", "management.endpoints.web.exposure.include=*\n");
    write("src/main/java/App.java", "new SpelExpressionParser().parseExpression(request.getParameter(\"expr\")).getValue();\n");
    write("dotnet/AdminController.cs", "[AllowAnonymous] [HttpPost(\"/admin/users\")] public IActionResult Update(Request r) => Ok();\n");
    write("routes/web.php", "<?php User::create($request->all());\n");
    write("src/Controller/AdminController.php", "#[Route('/admin/users')] public function update(Request $request) { return new Response('ok'); }\n");
    write("go/main.go", "func h(c *gin.Context) { var input User; c.BindJSON(&input); db.Create(&input) }\n");
    write("rust/src/main.rs", "let app = Router::new().route(\"/admin\", post(update)); async fn update(Json(input): Json<Input>) {}\n");
    write("electron/preload.ts", "contextBridge.exposeInMainWorld('api', { run: (cmd) => exec(cmd) });\n");

    const stagePlan = new StageResolver().resolve({
      config: { ...DEFAULT_CONFIG, projectId: "frameworks", defaultStage: "campaign", stages: {} },
      cliOverrides: { stage: "campaign" }
    });
    const snapshot = await new RepositoryIngestor().ingest({
      rootPath: temp,
      runId: "framework_run",
      projectId: "frameworks",
      stagePlan
    });
    for (const tag of ["nextjs", "express", "fastify", "nestjs", "trpc", "graphql", "django", "fastapi", "rails", "spring", "dotnet", "laravel", "symfony", "gin", "axum", "electron"]) {
      assert.ok(snapshot.techProfile.tags.includes(tag), `expected tech detector to include ${tag}`);
    }
    const signals = await new MatcherEngine().run({ snapshot, stagePlan });
    const signalSlugs = new Set(signals.map((signal) => signal.slug));
    const expected = [
      "nextjs-server-action-missing-authorization",
      "nextjs-route-handler-untrusted-redirect",
      "express-route-missing-authorization",
      "express-webhook-signature-gap",
      "fastify-body-missing-schema",
      "nestjs-controller-missing-guard",
      "trpc-public-procedure-mutates-state",
      "graphql-resolver-missing-auth",
      "django-csrf-exempt-state-change",
      "django-raw-sql-format-string",
      "fastapi-route-missing-dependency-auth",
      "rails-authentication-skipped",
      "rails-request-all-mass-assignment",
      "spring-actuator-wildcard-exposure",
      "spring-spel-user-input",
      "dotnet-allowanonymous-sensitive-action",
      "laravel-request-all-mass-assignment",
      "symfony-route-missing-access-control",
      "gin-binding-without-validation",
      "rust-axum-state-change-without-extractor-auth",
      "electron-preload-exposes-shell"
    ];
    const missing = expected.filter((slug) => !signalSlugs.has(slug));
    assert.deepEqual(missing, []);
  }],
  ["Scanner catalog and external tool registry expose operational depth", async () => {
    const summary = buildCatalogSummary();
    assert.ok(summary.total >= 450);
    assert.ok(summary.technologyDetectors >= 40);
    assert.ok((summary.byCategory.auth ?? 0) >= 20);
    assert.ok(summary.frameworks.includes("nextjs"));
    assert.ok(summary.frameworks.includes("spring"));
    const registry = createDefaultExternalToolRegistry();
    assert.ok(registry.get("semgrep"));
    assert.ok(registry.get("trivy"));
    assert.ok(registry.get("codeql"));
    const sandbox = new CommandSandboxPolicy(new Set(["semgrep"]));
    const blockedBinary = sandbox.validate({ binary: "powershell", args: ["-Command", "whoami"] });
    assert.equal(blockedBinary.allowed, false);
    const blockedRun = runCommand("powershell", ["-Command", "whoami"], { sandbox });
    assert.equal(blockedRun.exitCode, 126);
  }],
  ["Seeded security-surface matchers detect representative framework families", async () => {
    const temp = makeTempProject("proofstrike-security-surfaces");
    const write = (relPath: string, content: string) => {
      const target = path.join(temp, relPath);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, content, "utf8");
    };
    write("src/server.ts", [
      "app.get('/users', (req, res) => res.json([]));",
      "fastify.get('/health', async () => ({}));",
      "const html = element.innerHTML;",
      "window.addEventListener('message', (event) => console.log(event.data));",
      "cache.set(req.query.key, req.body.value);",
      "@RestResource(urlMapping='/v1/users/*')",
      "if (process.env.DISABLE_AUTH) return true;"
    ].join("\n"));
    write("go/main.go", "r := gin.Default()\nr.GET(\"/users\", handler)\n");
    write("rust/src/lib.rs", "let app = Router::new().route(\"/users\", get(handler));\n");
    write("php/routes.php", "<?php Route::get('/users', 'UserController@index');");
    write("java/App.java", "@RestController class Users { @GetMapping(\"/users\") void users() {} }");
    write("dotnet/Program.cs", "var app = WebApplication.Create(); app.MapGet(\"/users\", () => Results.Ok());");
    write("swift/routes.swift", "import Vapor\nfunc routes(_ app: Application) throws { app.get(\"users\") { req in \"ok\" } }");
    write("force/Api.cls", "@RestResource(urlMapping='/v1/users/*') global with sharing class Api { @HttpGet global static void get() {} }");
    write("infra/main.tf", "resource \"aws_security_group\" \"web\" { ingress { cidr_blocks = [\"0.0.0.0/0\"] } }");
    write("clj/handler.clj", "(defroutes app (GET \"/users\" [] \"ok\"))");
    write("elixir/user_controller.ex", "defmodule MyAppWeb.UserController do\n  use MyAppWeb, :controller\nend");
    write("erlang/handler.erl", "init(Req, State) -> cowboy_req:reply(200, Req), {ok, Req, State}.");
    write("crystal/app.cr", "require \"kemal\"\nget \"/users\" do\n  \"ok\"\nend");
    write("dart/server.dart", "import 'package:shelf/shelf.dart';\nResponse handler(Request request) => Response.ok('ok');");
    write("lua/nginx.lua", "ngx.exec('/internal')");

    const stagePlan = new StageResolver().resolve({
      config: { ...DEFAULT_CONFIG, projectId: "surface", defaultStage: "campaign", stages: {} },
      cliOverrides: { stage: "campaign" }
    });
    const snapshot = await new RepositoryIngestor().ingest({
      rootPath: temp,
      runId: "surface_run",
      projectId: "surface",
      stagePlan
    });
    const scopedPaths = new Set(snapshot.files.map((file) => file.filePath));
    for (const relPath of [
      "force/Api.cls",
      "clj/handler.clj",
      "elixir/user_controller.ex",
      "erlang/handler.erl",
      "crystal/app.cr",
      "dart/server.dart",
      "swift/routes.swift",
      "lua/nginx.lua"
    ]) {
      assert.ok(scopedPaths.has(relPath), `ingestor should include ${relPath}`);
    }

    const signals = await new MatcherEngine().run({ snapshot, stagePlan });
    const signalSlugs = new Set(signals.map((signal) => signal.slug));
    const expected = [
      "surface-express-http-entrypoint",
      "surface-fastify-http-entrypoint",
      "surface-web-postmessage-origin",
      "surface-cache-poisoning-vector",
      "surface-auth-development-bypass",
      "surface-go-gin-route",
      "surface-rust-axum-route",
      "surface-php-laravel-route",
      "surface-jvm-spring-controller",
      "surface-dotnet-minimal-api",
      "surface-swift-vapor-route",
      "surface-apex-rest-resource",
      "surface-terraform-public-ingress",
      "surface-clojure-ring-handler",
      "surface-elixir-phoenix-controller",
      "surface-erlang-cowboy-handler",
      "surface-crystal-kemal-route",
      "surface-dart-shelf-handler",
      "surface-lua-nginx-handler"
    ];
    const missing = expected.filter((slug) => !signalSlugs.has(slug));
    assert.deepEqual(missing, []);
  }],
  ["ReviewRunner completes source review and produces policy decisions", async () => {
    const temp = makeTempProject("proofstrike-review");
    copyFixture(fixtureRoot, temp);
    const result = await new ReviewRunner().run({
      rootPath: temp,
      config: { ...DEFAULT_CONFIG, projectId: "fixture", stages: {} },
      stage: "stage",
      explicitFiles: ["src/api/users.ts", "src/api/admin.ts", "src/api/webhook.ts"]
    });
    assert.equal(result.stagePlan.name, "stage");
    assert.ok(result.signals.length >= 3);
    assert.ok(result.findings.length >= 2);
    assert.equal(result.validations.length, result.findings.length);
    assert.ok(result.workPackets.every((packet) => packet.status === "done"));
    assert.deepEqual(result.store.getRun(result.runId)?.errors, []);
    assert.ok(fs.existsSync(path.join(temp, ".proofstrike", "proofstrike-data.json")));
  }],
  ["ReviewRunner resumes queued or errored work packets from stored state", async () => {
    const temp = makeTempProject("proofstrike-resume");
    copyFixture(fixtureRoot, temp);
    const config = { ...DEFAULT_CONFIG, projectId: "fixture", stages: {} };
    const result = await new ReviewRunner().run({
      rootPath: temp,
      config,
      stage: "stage",
      explicitFiles: ["src/api/users.ts"]
    });
    const packet = result.workPackets[0];
    assert.ok(packet);
    result.store.updateWorkPacket(packet.id, { status: "error" });
    result.store.completeRun(result.runId, { status: "error", errors: ["simulated interrupted packet"] });
    const resumed = await new ReviewRunner().resume({
      rootPath: temp,
      config,
      runId: result.runId,
      store: result.store
    });
    assert.equal(resumed.runId, result.runId);
    assert.ok(resumed.workPackets.every((item) => item.status === "done"));
    assert.notEqual(resumed.store.getRun(result.runId)?.status, "error");
  }],
  ["Scoped clean files get model-review coverage without false static findings", async () => {
    const temp = makeTempProject("proofstrike-scope-review");
    copyFixture(fixtureRoot, temp);
    const result = await new ReviewRunner().run({
      rootPath: temp,
      config: { ...DEFAULT_CONFIG, projectId: "fixture", stages: {} },
      stage: "pull_request",
      explicitFiles: ["src/api/safe.ts"]
    });
    assert.equal(result.snapshot.scopeSource, "explicit_files");
    assert.ok(result.signals.some((signal) => signal.slug === "scope-review"));
    assert.equal(result.workPackets.length, 1);
    assert.equal(result.findings.length, 0);
    assert.equal(result.policyDecisions.length, 0);
  }],
  ["Configured failOn policy rules control release decisions", async () => {
    const temp = makeTempProject("proofstrike-policy-fail");
    copyFixture(fixtureRoot, temp);
    const config = {
      ...DEFAULT_CONFIG,
      projectId: "fixture",
      stages: {},
      failOn: [{ id: "block-injection", category: "injection", reason: "Injection blocks this gate." }],
      manualReviewOn: [],
      suppressions: []
    };
    const result = await new ReviewRunner().run({
      rootPath: temp,
      config,
      stage: "stage",
      explicitFiles: ["src/api/users.ts"]
    });
    const injection = result.findings.find((finding) => finding.category === "injection");
    assert.ok(injection);
    const decision = result.policyDecisions.find((item) => item.findingId === injection.id);
    assert.equal(decision?.decision, "fail");
    assert.equal(decision?.ruleId, "block-injection");
  }],
  ["Config suppressions and accepted risks override blocking policy", async () => {
    const temp = makeTempProject("proofstrike-policy-suppression");
    copyFixture(fixtureRoot, temp);
    const config = {
      ...DEFAULT_CONFIG,
      projectId: "fixture",
      stages: {},
      failOn: [{ id: "block-injection", category: "injection" }],
      manualReviewOn: [],
      suppressions: [{
        id: "accepted-users-injection",
        path: "src/api/users.ts",
        category: "injection",
        status: "accepted_risk" as const,
        reason: "Fixture accepted only for policy testing."
      }]
    };
    const result = await new ReviewRunner().run({
      rootPath: temp,
      config,
      stage: "stage",
      explicitFiles: ["src/api/users.ts"]
    });
    const injection = result.findings.find((finding) => finding.category === "injection");
    assert.ok(injection);
    const decision = result.policyDecisions.find((item) => item.findingId === injection.id);
    assert.equal(decision?.decision, "pass");
    assert.equal(decision?.ruleId, "accepted-users-injection");
  }],
  ["RepositoryIngestor respects configured instructions, hotspots, and local knowledge", async () => {
    const temp = makeTempProject("proofstrike-configured-context");
    copyFixture(fixtureRoot, temp);
    fs.mkdirSync(path.join(temp, ".proofstrike", "knowledge"), { recursive: true });
    fs.writeFileSync(path.join(temp, ".proofstrike", "custom-instructions.md"), "Custom auth model.", "utf8");
    fs.writeFileSync(path.join(temp, ".proofstrike", "knowledge", "tenant.md"), "Local tenant knowledge.", "utf8");
    fs.writeFileSync(
      path.join(temp, ".proofstrike", "custom-hotspots.yml"),
      [
        "hotspots:",
        "  - id: users-route",
        "    paths:",
        "      - src/api/users.ts",
        "    reason: User API boundary.",
        ""
      ].join("\n"),
      "utf8"
    );
    const config = {
      ...DEFAULT_CONFIG,
      projectId: "fixture",
      instructions: [".proofstrike/custom-instructions.md"],
      hotspots: [".proofstrike/custom-hotspots.yml"],
      stages: {}
    };
    const snapshot = await new RepositoryIngestor().ingest({
      rootPath: temp,
      runId: "context_run",
      projectId: "fixture",
      stagePlan: new StageResolver().resolve({ config, cliOverrides: { stage: "stage" } }),
      explicitFiles: ["src/api/users.ts"],
      config
    });
    assert.ok(snapshot.instructions.some((instruction) => instruction.path === ".proofstrike/custom-instructions.md"));
    assert.ok(snapshot.instructions.some((instruction) => instruction.path === ".proofstrike/knowledge/tenant.md"));
    assert.ok(snapshot.hotspots.some((hotspot) => hotspot.id === "users-route"));
  }],
  ["ReviewRunner loads local matcher packs, enriches context, and writes run artifacts", async () => {
    const temp = makeTempProject("proofstrike-operational-depth");
    copyFixture(fixtureRoot, temp);
    fs.mkdirSync(path.join(temp, ".proofstrike"), { recursive: true });
    fs.writeFileSync(path.join(temp, "CODEOWNERS"), "src/api/* @security-team\n", "utf8");
    fs.writeFileSync(
      path.join(temp, ".proofstrike", "custom-matchers.json"),
      JSON.stringify({
        matchers: [{
          slug: "custom-tenant-id-query",
          name: "Tenant id read directly from request query",
          category: "auth",
          severity: "high",
          confidence: "high",
          noiseTier: "low",
          pattern: "db\\.tenant[\\s\\S]{0,240}req\\.query\\.tenantId|req\\.query\\.tenantId[\\s\\S]{0,240}db\\.tenant",
          message: "Tenant lookup appears to trust tenant id from the request query.",
          examples: ["const tenant = await db.tenant.find(req.query.tenantId);"]
        }]
      }, null, 2),
      "utf8"
    );
    fs.writeFileSync(
      path.join(temp, "src", "api", "tenant.ts"),
      "export async function GET(req) { const tenant = await db.tenant.find(req.query.tenantId); return tenant; }\n",
      "utf8"
    );
    const config = {
      ...DEFAULT_CONFIG,
      projectId: "fixture",
      packs: ["proofstrike.builtins", ".proofstrike/custom-matchers.json"],
      stages: {}
    };
    const result = await new ReviewRunner().run({
      rootPath: temp,
      config,
      stage: "stage",
      explicitFiles: ["src/api/tenant.ts", "package.json"]
    });
    assert.ok(result.signals.some((signal) => signal.slug === "custom-tenant-id-query"));
    assert.ok(result.evidence.some((item) => item.source === "proofstrike.enrichment.tech-profile"));
    assert.ok(result.evidence.some((item) => item.source === "proofstrike.enrichment.ownership"));
    const artifactRoot = path.join(temp, ".proofstrike", "artifacts", result.runId);
    for (const artifact of ["snapshot.json", "code-index.json", "signals.json", "candidates.json", "work-packets.json", "findings.json", "validations.json", "policy-decisions.json"]) {
      assert.ok(fs.existsSync(path.join(artifactRoot, artifact)), `missing artifact ${artifact}`);
    }
  }],
  ["Extension registry contributes matchers, ownership, and notifications", async () => {
    const temp = makeTempProject("proofstrike-extensions");
    copyFixture(fixtureRoot, temp);
    fs.writeFileSync(
      path.join(temp, "src", "api", "critical.ts"),
      "export function GET(req) { const token = 'critical-extension-secret-value'; return token; }\n",
      "utf8"
    );
    const notifications: NotificationRecord[] = [];
    const extensions = new ExtensionRegistry([{
      name: "test-extension",
      matchers: [regexMatcher({
        slug: "extension-critical-secret",
        name: "Extension critical secret",
        category: "secrets",
        severity: "critical",
        confidence: "high",
        noiseTier: "low",
        pattern: /critical-extension-secret-value/,
        message: "Extension matcher found a critical secret."
      })],
      ownership: {
        name: "test-owner",
        async fetchOwnership(params) {
          return params.filePath.endsWith("critical.ts")
            ? { owners: ["security@example.com"], source: "test-owner" }
            : null;
        }
      },
      notifiers: [{
        name: "test-notifier",
        async notify(params) {
          const record = {
            notifierName: "test-notifier",
            findingId: params.finding.id,
            notifiedAt: "2026-01-01T00:00:00.000Z",
            externalId: "ticket-1"
          };
          notifications.push(record);
          return record;
        }
      }]
    }]);
    const result = await ReviewRunner.withExtensions(extensions).run({
      rootPath: temp,
      config: { ...DEFAULT_CONFIG, projectId: "fixture", stages: {} },
      stage: "stage",
      explicitFiles: ["src/api/critical.ts"]
    });
    assert.ok(result.signals.some((signal) => signal.slug === "extension-critical-secret"));
    assert.ok(result.evidence.some((item) =>
      item.source === "proofstrike.enrichment.ownership" &&
      JSON.stringify(item.raw).includes("security@example.com")
    ));
    assert.ok(result.policyDecisions.some((decision) => decision.decision === "fail"));
    assert.ok(notifications.length >= 1);
    assert.equal(result.notifications.length, notifications.length);
  }],
  ["Preflight fails loudly for invalid packs and missing model credentials", async () => {
    const temp = makeTempProject("proofstrike-preflight");
    copyFixture(fixtureRoot, temp);
    const invalidPack = await runPreflight({
      rootPath: temp,
      config: {
        ...DEFAULT_CONFIG,
        projectId: "fixture",
        packs: [".proofstrike/missing-pack.json"],
        stages: {}
      }
    });
    assert.equal(invalidPack.ok, false);
    assert.ok(invalidPack.issues.some((issue) => issue.code === "matcher_pack_invalid"));
    const missingModel = await runPreflight({
      rootPath: temp,
      config: {
        ...DEFAULT_CONFIG,
        projectId: "fixture",
        providers: { default: { baseUrl: "https://models.example.invalid", apiKeyEnv: "PROOFSTRIKE_TEST_MISSING_KEY", defaultModel: "model" } },
        stages: {}
      },
      requireModel: true
    });
    assert.equal(missingModel.ok, false);
    assert.ok(missingModel.issues.some((issue) => issue.code === "model_credentials_missing"));
  }],
  ["File-state tracking supports repeat incremental CI scopes", async () => {
    const temp = makeTempProject("proofstrike-file-state-ci");
    copyFixture(fixtureRoot, temp);
    const config = { ...DEFAULT_CONFIG, projectId: "fixture", stages: {} };
    const first = await new ReviewRunner().run({
      rootPath: temp,
      config,
      stage: "dev"
    });
    assert.ok(first.store.data.fileStates.length > 0);
    assert.deepEqual(changedFilesSinceLastRun(temp, first.store.data, config.projectId), []);
    const usersPath = path.join(temp, "src", "api", "users.ts");
    fs.appendFileSync(usersPath, "\n// security-relevant edit\n", "utf8");
    const changed = changedFilesSinceLastRun(temp, first.store.data, config.projectId);
    assert.deepEqual(changed, ["src/api/users.ts"]);
  }],
  ["Lifecycle helpers summarize, export, triage, and explain stored evidence", async () => {
    const temp = makeTempProject("proofstrike-lifecycle");
    copyFixture(fixtureRoot, temp);
    const config = { ...DEFAULT_CONFIG, projectId: "fixture", stages: {} };
    const result = await new ReviewRunner().run({
      rootPath: temp,
      config,
      stage: "stage",
      explicitFiles: ["src/api/users.ts", "src/api/admin.ts", "src/api/webhook.ts"]
    });
    const status = buildStatusSummary(result.store.data, config);
    assert.equal(status.projectId, "fixture");
    assert.equal(status.findings.total, result.findings.length);

    const bundle = buildExportBundle({ data: result.store.data, config, includeResolved: true });
    assert.equal(bundle.findings.length, result.findings.length);
    assert.ok(bundle.findings[0]?.evidence.length);

    const metrics = computeMetrics({ data: result.store.data, config, minSeverity: "info" });
    assert.equal(metrics.signals.total, result.signals.length);
    assert.equal(metrics.findings.total, result.findings.length);

    const controls = buildControlReport({
      findings: result.findings,
      validations: result.validations,
      policyDecisions: result.policyDecisions
    });
    assert.ok(controls.releaseRisk.score > 0);
    assert.ok(Object.keys(controls.byStandard).length > 0);

    const triage = triageFindings({ data: result.store.data, config, minSeverity: "medium" });
    assert.ok(triage.items.length > 0);
    assert.ok(triage.counts.P0 + triage.counts.P1 + triage.counts.P2 + triage.counts.skip >= triage.items.length);

    const explanation = explainFinding({ data: result.store.data, config, findingId: result.findings[0]!.id });
    assert.equal(explanation.finding.id, result.findings[0]!.id);
    assert.ok(explanation.evidence.length > 0);
  }],
  ["Revalidation reruns matchers and marks fixed root causes", async () => {
    const temp = makeTempProject("proofstrike-revalidate");
    copyFixture(fixtureRoot, temp);
    const config = { ...DEFAULT_CONFIG, projectId: "fixture", stages: {} };
    const review = await new ReviewRunner().run({
      rootPath: temp,
      config,
      stage: "stage",
      explicitFiles: ["src/api/users.ts"]
    });
    assert.ok(review.findings.some((finding) => finding.category === "injection"));

    const usersPath = path.join(temp, "src", "api", "users.ts");
    const original = fs.readFileSync(usersPath, "utf8");
    fs.writeFileSync(
      usersPath,
      original.replace(
        "db.query(\"select * from users where name = '\" + term + \"'\")",
        "db.query(\"select * from users where name = $1\", [term])"
      ),
      "utf8"
    );

    const result = await new RevalidationRunner().run({ rootPath: temp, config, store: review.store });
    const fixedInjection = result.findings.find((finding) => finding.category === "injection");
    assert.ok(fixedInjection);
    assert.equal(fixedInjection.status, "fixed");
    assert.ok(result.fixed >= 1);
  }],
  ["PromptCompiler produces bounded model prompts with signals and knowledge", async () => {
    const snapshot = await new RepositoryIngestor().ingest({
      rootPath: fixtureRoot,
      runId: "prompt_run",
      projectId: "fixture",
      stagePlan: new StageResolver().resolve({
        config: { ...DEFAULT_CONFIG, projectId: "fixture" },
        cliOverrides: { stage: "stage" }
      }),
      explicitFiles: ["src/api/users.ts"]
    });
    const signals = await new MatcherEngine().run({ snapshot, stagePlan: { matcherProfile: "balanced" } });
    const asset = snapshot.files[0];
    assert.ok(asset);
    const prompt = new PromptCompiler().compileInvestigation({
      workPacket: {
        id: "packet_prompt",
        runId: "prompt_run",
        projectId: "fixture",
        stage: "stage",
        agentKind: "static-investigator",
        primaryAssetId: asset.id,
        assetIds: [asset.id],
        candidateIds: ["candidate_prompt"],
        signalIds: signals.map((signal) => signal.id),
        codeContext: [],
        graphContext: [],
        knowledgePackIds: ["core-review"],
        projectInstructionIds: [],
        historyRefs: [],
        budget: { maxCostUsd: 1, maxPromptChars: 12000 },
        outputSchema: "finding_array",
        status: "queued"
      },
      snapshot,
      assets: [asset],
      signals,
      renderedKnowledge: { packIds: ["core-review"], text: "Check source, sink, trust boundary, and mitigation." }
    });
    assert.equal(prompt.schemaName, "proofstrike_investigation_findings");
    assert.ok(prompt.promptChars > 1000);
    assert.ok(prompt.messages.some((message) => message.content.includes("sql-injection")));
    assert.ok(prompt.messages.some((message) => message.content.includes("Security triage rules")));
    assert.ok(prompt.messages.some((message) => message.content.includes("Reject false positives")));
  }],
  ["Agentic repository investigator reads files before issuing supported findings", async () => {
    const stagePlan = new StageResolver().resolve({
      config: { ...DEFAULT_CONFIG, projectId: "fixture", stages: {} },
      cliOverrides: { stage: "stage" }
    });
    const snapshot = await new RepositoryIngestor().ingest({
      rootPath: fixtureRoot,
      runId: "agentic_loop_run",
      projectId: "fixture",
      stagePlan,
      explicitFiles: ["src/api/users.ts"]
    });
    const signals = await new MatcherEngine().run({ snapshot, stagePlan });
    const asset = snapshot.files[0];
    assert.ok(asset);
    let calls = 0;
    const gateway: ModelGateway = {
      async chatJson<T>() {
        calls += 1;
        if (calls === 1) return { action: "read_files", files: ["src/api/users.ts"] } as T;
        return {
          action: "finish",
          findings: [{
            slug: "sql-injection",
            title: "Raw SQL with interpolation",
            category: "injection",
            severity: "high",
            confidence: "high",
            summary: "Request input reaches a SQL query string.",
            technicalDetails: "The users route concatenates req.query.q into a SQL query.",
            impact: "Attackers may alter the query.",
            recommendation: "Use parameterized queries.",
            lineNumbers: [6],
            cwe: ["CWE-89"]
          }]
        } as T;
      }
    };
    const agent = new AgenticRepositoryInvestigatorAgent(gateway, new PromptCompiler(), "test-model", {
      maxTurns: 3,
      allowStaticFallback: false
    });
    const output = await agent.investigate({
      workPacket: {
        id: "packet_agentic_loop",
        runId: "agentic_loop_run",
        projectId: "fixture",
        stage: "stage",
        agentKind: "repository-explorer-investigator",
        primaryAssetId: asset.id,
        assetIds: [asset.id],
        candidateIds: ["candidate_agentic_loop"],
        signalIds: signals.map((signal) => signal.id),
        codeContext: [],
        graphContext: [],
        knowledgePackIds: ["core-review"],
        projectInstructionIds: [],
        historyRefs: [],
        budget: { maxCostUsd: 1, maxPromptChars: 12000, maxToolCalls: 3 },
        outputSchema: "finding_array",
        status: "queued"
      },
      snapshot,
      assets: [asset],
      signals,
      renderedKnowledge: { packIds: ["core-review"], text: "Check source, sink, and mitigation." }
    });
    assert.equal(calls, 2);
    assert.equal(output.findings[0]?.category, "injection");
    assert.ok(output.evidence.some((item) => item.summary.includes("read 1 file")));
    assert.ok(output.usage?.[0]?.estimatedPromptTokens);
  }],
  ["Model-backed investigator can fail loudly when fallback is disabled", async () => {
    const stagePlan = new StageResolver().resolve({
      config: { ...DEFAULT_CONFIG, projectId: "fixture", stages: {} },
      cliOverrides: { stage: "stage" }
    });
    const snapshot = await new RepositoryIngestor().ingest({
      rootPath: fixtureRoot,
      runId: "model_fail_loud_run",
      projectId: "fixture",
      stagePlan,
      explicitFiles: ["src/api/users.ts"]
    });
    const signals = await new MatcherEngine().run({ snapshot, stagePlan });
    const asset = snapshot.files[0];
    assert.ok(asset);
    const gateway: ModelGateway = {
      async chatJson() {
        throw new Error("simulated provider outage");
      }
    };
    const agent = new ModelBackedInvestigatorAgent(gateway, new PromptCompiler(), "test-model", undefined, {
      allowStaticFallback: false,
      maxRetries: 1
    });
    await assert.rejects(
      () => agent.investigate({
        workPacket: {
          id: "packet_model_fail_loud",
          runId: "model_fail_loud_run",
          projectId: "fixture",
          stage: "stage",
          agentKind: "model-backed-investigator",
          primaryAssetId: asset.id,
          assetIds: [asset.id],
          candidateIds: ["candidate_model_fail_loud"],
          signalIds: signals.map((signal) => signal.id),
          codeContext: [],
          graphContext: [],
          knowledgePackIds: ["core-review"],
          projectInstructionIds: [],
          historyRefs: [],
          budget: { maxCostUsd: 1, maxPromptChars: 12000 },
          outputSchema: "finding_array",
          status: "queued"
        },
        snapshot,
        assets: [asset],
        signals,
        renderedKnowledge: { packIds: ["core-review"], text: "Check source and sink evidence." }
      }),
      (error) => error instanceof AgentExecutionError && error.reason === "model_gateway_error"
    );
  }],
  ["Model-backed investigator records fallback diagnostics", async () => {
    const stagePlan = new StageResolver().resolve({
      config: { ...DEFAULT_CONFIG, projectId: "fixture", stages: {} },
      cliOverrides: { stage: "stage" }
    });
    const snapshot = await new RepositoryIngestor().ingest({
      rootPath: fixtureRoot,
      runId: "model_fallback_run",
      projectId: "fixture",
      stagePlan,
      explicitFiles: ["src/api/users.ts"]
    });
    const signals = await new MatcherEngine().run({ snapshot, stagePlan });
    const asset = snapshot.files[0];
    assert.ok(asset);
    const gateway: ModelGateway = {
      async chatJson() {
        throw new Error("simulated provider failure");
      }
    };
    const agent = new ModelBackedInvestigatorAgent(gateway, new PromptCompiler(), "test-model");
    const output = await agent.investigate({
      workPacket: {
        id: "packet_model_fallback",
        runId: "model_fallback_run",
        projectId: "fixture",
        stage: "stage",
        agentKind: "model-backed-investigator",
        primaryAssetId: asset.id,
        assetIds: [asset.id],
        candidateIds: ["candidate_model_fallback"],
        signalIds: signals.map((signal) => signal.id),
        codeContext: [],
        graphContext: [],
        knowledgePackIds: ["core-review"],
        projectInstructionIds: [],
        historyRefs: [],
        budget: { maxCostUsd: 1, maxPromptChars: 12000 },
        outputSchema: "finding_array",
        status: "queued"
      },
      snapshot,
      assets: [asset],
      signals,
      renderedKnowledge: { packIds: ["core-review"], text: "Check source and sink evidence." }
    });
    assert.ok(output.findings.some((finding) => finding.category === "injection"));
    const diagnostic = output.evidence.find((item) => item.source === "model-backed-investigator" && item.kind === "artifact");
    assert.ok(diagnostic);
    assert.match(diagnostic.summary, /fell back/);
    assert.equal((diagnostic.raw as { model?: string }).model, "test-model");
  }],
  ["PackManager installs and audits a pack reference", async () => {
    const temp = makeTempProject("proofstrike-pack");
    const manager = new PackManager(temp);
    const pack = manager.install("npm:@proofstrike/web-auth");
    assert.equal(pack.id, "proofstrike.web-auth");
    assert.equal(manager.audit().ok, true);
  }]
];

let passed = 0;
for (const [name, fn] of tests) {
  try {
    await fn();
    passed += 1;
    console.log(`ok - ${name}`);
  } catch (error) {
    console.error(`not ok - ${name}`);
    console.error(error);
    process.exitCode = 1;
    break;
  }
}

if (!process.exitCode) {
  console.log(`${passed}/${tests.length} tests passed`);
}

import type { Confidence, Severity, Signal } from "../../core/src/index.js";
import type { FileAsset } from "../../ingest/src/index.js";
import type { MatcherContext, MatcherPlugin } from "./index.js";

interface FrameworkRule {
  slug: string;
  name: string;
  category: string;
  severity: Severity;
  confidence: Confidence;
  noiseTier: "low" | "medium" | "high";
  frameworks: string[];
  filePatterns?: RegExp[];
  include?: (text: string, asset: FileAsset) => boolean;
  pattern: RegExp;
  negativePattern?: RegExp;
  message: string;
  examples: string[];
}

export function createFrameworkSpecialistMatchers(): MatcherPlugin[] {
  return FRAMEWORK_RULES.map(frameworkRuleMatcher);
}

export const FRAMEWORK_RULES: readonly FrameworkRule[] = Object.freeze([
  {
    slug: "nextjs-server-action-missing-authorization",
    name: "Next.js server action without local authorization",
    category: "auth",
    severity: "high",
    confidence: "medium",
    noiseTier: "low",
    frameworks: ["nextjs"],
    filePatterns: [/^app\//i],
    pattern: /["']use server["'][\s\S]{0,1800}\bexport\s+async\s+function\b[\s\S]{0,1800}\b(?:formData|request|params|cookies\(\)|headers\(\))/i,
    negativePattern: /\b(?:requireAuth|requireUser|requireAdmin|authorize|assertRole|getServerSession|auth\(|currentUser|verifyToken|permission)\b/i,
    message: "Server action accepts request-controlled input without an obvious local authorization check.",
    examples: ["'use server'; export async function updateUser(formData) { await db.user.update(...) }"]
  },
  {
    slug: "nextjs-route-handler-untrusted-redirect",
    name: "Next.js route handler redirects to request-controlled URL",
    category: "ssrf",
    severity: "high",
    confidence: "medium",
    noiseTier: "low",
    frameworks: ["nextjs"],
    filePatterns: [/route\.(?:ts|js)$/i, /^pages\/api\//i],
    pattern: /\b(?:NextResponse\.redirect|redirect)\s*\([^)]*(?:searchParams\.get|req\.query|request\.url|headers\(\)\.get)\b/i,
    negativePattern: /\b(?:allowlist|allowedRedirect|safeRedirect|sameOrigin|new URL\([^)]*origin)\b/i,
    message: "Route handler appears to redirect to request-controlled data without an allowlist.",
    examples: ["return NextResponse.redirect(req.nextUrl.searchParams.get('next'))"]
  },
  {
    slug: "express-route-missing-authorization",
    name: "Express route without local authorization",
    category: "auth",
    severity: "high",
    confidence: "medium",
    noiseTier: "low",
    frameworks: ["express"],
    pattern: /\b(?:app|router)\.(?:post|put|patch|delete|get)\s*\(\s*["'`][^"'`]*(?:admin|user|account|billing|tenant|api)[^"'`]*/i,
    negativePattern: /\b(?:requireAuth|requireUser|requireAdmin|authorize|isAuthenticated|passport\.authenticate|verifyToken|checkRole|permission)\b/i,
    message: "Express route exposes sensitive-looking functionality without a nearby auth guard.",
    examples: ["router.post('/admin/users', async (req, res) => updateUser(req.body))"]
  },
  {
    slug: "express-webhook-signature-gap",
    name: "Express webhook handler without signature verification",
    category: "auth",
    severity: "high",
    confidence: "medium",
    noiseTier: "low",
    frameworks: ["express"],
    include: (text, asset) => /webhook|stripe|github|slack/i.test(asset.filePath) || /webhook|stripe|github|slack/i.test(text),
    pattern: /\b(?:app|router)\.post\s*\([^)]*(?:webhook|stripe|github|slack)[\s\S]{0,1600}\b(?:req\.body|request\.body|express\.json)\b/i,
    negativePattern: /\b(?:signature|constructEvent|x-hub-signature|x-slack-signature|verifyWebhook|verifySignature|timingSafeEqual)\b/i,
    message: "Webhook-like Express handler parses a body without obvious signature verification.",
    examples: ["router.post('/webhook', express.json(), (req, res) => handle(req.body))"]
  },
  {
    slug: "fastify-body-missing-schema",
    name: "Fastify request body without route schema",
    category: "input-validation",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    frameworks: ["fastify"],
    pattern: /\bfastify\.(?:post|put|patch)\s*\([\s\S]{0,1400}\brequest\.body\b/i,
    negativePattern: /\bschema\s*:\s*\{|\bpreValidation\b|\bvalidatorCompiler\b|\bzod\b|\btypebox\b/i,
    message: "Fastify route reads request.body without an obvious schema or validation hook.",
    examples: ["fastify.post('/users', async (request) => db.user.create(request.body))"]
  },
  {
    slug: "nestjs-controller-missing-guard",
    name: "NestJS controller without guard",
    category: "auth",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    frameworks: ["nestjs"],
    pattern: /@Controller\b[\s\S]{0,2200}@(?:Post|Put|Patch|Delete|Get)\b[\s\S]{0,1200}\b(?:Body|Param|Query)\b/i,
    negativePattern: /@UseGuards\b|\bAuthGuard\b|\bRoles\b|\bPermissions\b/i,
    message: "NestJS controller method handles request input without an obvious guard decorator.",
    examples: ["@Controller('admin') export class Admin { @Post() update(@Body() body) { ... } }"]
  },
  {
    slug: "trpc-public-procedure-mutates-state",
    name: "tRPC public procedure mutates state",
    category: "auth",
    severity: "high",
    confidence: "medium",
    noiseTier: "low",
    frameworks: ["trpc"],
    pattern: /\bpublicProcedure\b[\s\S]{0,1600}\b\.mutation\s*\([\s\S]{0,1600}\b(?:create|update|delete|insert|upsert|execute|queryRaw)\b/i,
    negativePattern: /\b(?:protectedProcedure|requireAuth|ctx\.session|ctx\.user|authorize)\b/i,
    message: "Public tRPC mutation appears to perform a state-changing operation.",
    examples: ["publicProcedure.input(schema).mutation(({ input, ctx }) => ctx.db.user.update(input))"]
  },
  {
    slug: "graphql-resolver-missing-auth",
    name: "GraphQL mutation resolver without auth context",
    category: "auth",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    frameworks: ["graphql"],
    pattern: /\bMutation\s*[:{][\s\S]{0,2400}\b(?:create|update|delete|invite|admin)\w*\s*[:(][\s\S]{0,1800}\b(?:args|input)\b/i,
    negativePattern: /\b(?:context\.user|ctx\.user|requireAuth|authorize|ForbiddenError|AuthenticationError|shield|isAuthenticated)\b/i,
    message: "GraphQL mutation resolver uses input without an obvious auth context check.",
    examples: ["Mutation: { updateUser: (_, args) => db.user.update(args.input) }"]
  },
  {
    slug: "django-csrf-exempt-state-change",
    name: "Django CSRF exemption on state-changing view",
    category: "auth",
    severity: "high",
    confidence: "high",
    noiseTier: "low",
    frameworks: ["django"],
    pattern: /@csrf_exempt[\s\S]{0,1200}\b(?:POST|request\.body|request\.POST|save\(|delete\(|update\()/i,
    message: "Django view disables CSRF protection around state-changing behavior.",
    examples: ["@csrf_exempt\ndef update(request): User.objects.update(...)"]
  },
  {
    slug: "django-raw-sql-format-string",
    name: "Django raw SQL built with formatting",
    category: "injection",
    severity: "high",
    confidence: "high",
    noiseTier: "low",
    frameworks: ["django", "python"],
    pattern: /\b(?:cursor\.execute|\.raw)\s*\(\s*(?:f["'`]|["'`][\s\S]{0,160}(?:%|\+|\.format\())/i,
    negativePattern: /\bparams\s*=|\bsql.SQL\b|\bexecute\s*\([^,]+,\s*\[/i,
    message: "Django raw SQL appears to use string formatting instead of query parameters.",
    examples: ["cursor.execute(f\"select * from users where id = {request.GET['id']}\")"]
  },
  {
    slug: "fastapi-route-missing-dependency-auth",
    name: "FastAPI route without dependency-based auth",
    category: "auth",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    frameworks: ["fastapi"],
    pattern: /@\w+\.(?:post|put|patch|delete|get)\s*\([\s\S]{0,1600}\b(?:Request|Body|Query|Path|Form)\b/i,
    negativePattern: /\b(?:Depends|Security|OAuth2PasswordBearer|HTTPBearer|current_user|require_auth|verify_token)\b/i,
    message: "FastAPI route handles request input without an obvious auth dependency.",
    examples: ["@app.post('/admin')\ndef admin(payload: dict = Body(...)): ..."]
  },
  {
    slug: "rails-authentication-skipped",
    name: "Rails authentication callback skipped",
    category: "auth",
    severity: "high",
    confidence: "high",
    noiseTier: "low",
    frameworks: ["rails"],
    pattern: /\bskip_before_action\s+:(?:authenticate_user!?|require_login|authorize|verify_authenticity_token)/i,
    message: "Rails controller skips authentication or CSRF protection.",
    examples: ["skip_before_action :authenticate_user!"]
  },
  {
    slug: "rails-request-all-mass-assignment",
    name: "Rails mass assignment from request parameters",
    category: "authorization",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    frameworks: ["rails"],
    pattern: /\b(?:create|update|new)\s*\(\s*params(?:\[:\w+\])?\s*\)/i,
    negativePattern: /\bpermit\s*\(|\brequire\s*\([^)]*\)\.permit\b/i,
    message: "Rails model assignment appears to use raw params without strong-parameter filtering.",
    examples: ["User.update(params[:user])"]
  },
  {
    slug: "spring-actuator-wildcard-exposure",
    name: "Spring Actuator wildcard exposure",
    category: "exposure",
    severity: "high",
    confidence: "high",
    noiseTier: "low",
    frameworks: ["spring"],
    filePatterns: [/application\.(?:properties|ya?ml)$/i],
    pattern: /management\.endpoints\.web\.exposure\.include\s*[:=]\s*["']?\*|include:\s*["']?\*/i,
    message: "Spring Actuator appears configured to expose every web endpoint.",
    examples: ["management.endpoints.web.exposure.include=*"]
  },
  {
    slug: "spring-spel-user-input",
    name: "Spring expression evaluation with request input",
    category: "rce",
    severity: "critical",
    confidence: "medium",
    noiseTier: "medium",
    frameworks: ["spring", "jvm"],
    pattern: /\b(?:SpelExpressionParser|parseExpression)\b[\s\S]{0,1000}\b(?:request|getParameter|@RequestParam|body|param)\b/i,
    message: "Spring expression parsing appears connected to request-controlled input.",
    examples: ["parser.parseExpression(request.getParameter('expr')).getValue()"]
  },
  {
    slug: "dotnet-allowanonymous-sensitive-action",
    name: ".NET sensitive endpoint marked AllowAnonymous",
    category: "auth",
    severity: "high",
    confidence: "medium",
    noiseTier: "low",
    frameworks: ["dotnet"],
    pattern: /\[AllowAnonymous\][\s\S]{0,900}\[(?:HttpPost|HttpPut|HttpPatch|HttpDelete|Route)[^\]]*(?:admin|user|account|billing|tenant|token|password)/i,
    message: "Sensitive-looking .NET endpoint is explicitly anonymous.",
    examples: ["[AllowAnonymous] [HttpPost('/admin/users')] public IActionResult Update(...)"]
  },
  {
    slug: "laravel-request-all-mass-assignment",
    name: "Laravel mass assignment from request all",
    category: "authorization",
    severity: "high",
    confidence: "high",
    noiseTier: "low",
    frameworks: ["laravel"],
    pattern: /\b\w+::(?:create|update|firstOrCreate)\s*\(\s*\$request->all\s*\(\s*\)\s*\)/i,
    negativePattern: /\b(?:validated|only|safe)\s*\(/i,
    message: "Laravel model assignment uses all request fields instead of validated or allowlisted fields.",
    examples: ["User::create($request->all())"]
  },
  {
    slug: "symfony-route-missing-access-control",
    name: "Symfony route without access control hint",
    category: "auth",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    frameworks: ["symfony"],
    pattern: /#\[\s*Route\([^)]*(?:admin|user|account|billing|tenant)[\s\S]{0,1200}\bRequest\b/i,
    negativePattern: /\b(?:IsGranted|denyAccessUnlessGranted|security\.yaml|ROLE_|AuthorizationChecker)\b/i,
    message: "Symfony route handles sensitive-looking request input without an obvious access-control check.",
    examples: ["#[Route('/admin/users')] public function update(Request $request) { ... }"]
  },
  {
    slug: "gin-binding-without-validation",
    name: "Gin request binding without validation",
    category: "input-validation",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    frameworks: ["gin"],
    pattern: /\b(?:ShouldBind|BindJSON|BindQuery)\s*\([\s\S]{0,900}\b(?:Create|Update|Save|Exec|Query)\b/i,
    negativePattern: /\bbinding:"required|\bvalidator\.New\b|\bValidate\b|\bShouldBindWith\b/i,
    message: "Gin handler binds request data and uses it without an obvious validation step.",
    examples: ["c.BindJSON(&input); db.Create(&input)"]
  },
  {
    slug: "rust-axum-state-change-without-extractor-auth",
    name: "Axum state-changing route without auth extractor",
    category: "auth",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    frameworks: ["axum"],
    pattern: /Router::new\(\)[\s\S]{0,1200}\.route\([^)]*(?:post|put|patch|delete)\([^)]*\)[\s\S]{0,1200}\bJson\s*</i,
    negativePattern: /\b(?:Extension|State|TypedHeader|Auth|Claims|Session|Authorization)\b/i,
    message: "Axum state-changing route accepts JSON without an obvious auth extractor.",
    examples: ["Router::new().route('/admin', post(update)); async fn update(Json(input): Json<Input>)"]
  },
  {
    slug: "electron-preload-exposes-shell",
    name: "Electron preload exposes shell-like capability",
    category: "desktop-security",
    severity: "critical",
    confidence: "high",
    noiseTier: "low",
    frameworks: ["electron"],
    pattern: /\bcontextBridge\.exposeInMainWorld\b[\s\S]{0,1600}\b(?:exec|spawn|shell\.openExternal|ipcRenderer\.invoke)\b/i,
    negativePattern: /\b(?:allowlist|validateCommand|safeOpenExternal|URL\.canParse)\b/i,
    message: "Electron preload bridge appears to expose shell or IPC capabilities without an obvious allowlist.",
    examples: ["contextBridge.exposeInMainWorld('api', { run: (cmd) => exec(cmd) })"]
  }
]);

function frameworkRuleMatcher(rule: FrameworkRule): MatcherPlugin {
  return {
    slug: rule.slug,
    name: rule.name,
    category: rule.category,
    severity: rule.severity,
    confidence: rule.confidence,
    noiseTier: rule.noiseTier,
    frameworks: rule.frameworks,
    filePatterns: rule.filePatterns?.map((pattern) => pattern.source),
    examples: rule.examples,
    provenance: "proofstrike",
    async run(ctx: MatcherContext): Promise<Signal[]> {
      const signals: Signal[] = [];
      for (const asset of ctx.files()) {
        if (rule.filePatterns?.length && !rule.filePatterns.some((pattern) => pattern.test(asset.filePath))) continue;
        const text = ctx.readFile(asset.filePath);
        if (rule.include && !rule.include(text, asset)) continue;
        if (!rule.pattern.test(text)) continue;
        if (rule.negativePattern?.test(text)) continue;
        const match = firstMatch(text, rule.pattern);
        signals.push(ctx.signal({
          asset,
          slug: rule.slug,
          confidence: rule.confidence,
          weight: rule.confidence === "high" ? 1 : 0.78,
          lineNumbers: match ? [lineNumberForIndex(text, match.index)] : [1],
          snippet: match?.text,
          message: rule.message,
          raw: {
            slug: rule.slug,
            category: rule.category,
            severity: rule.severity,
            matcher: rule.name,
            frameworkRule: true
          }
        }));
      }
      return signals;
    }
  };
}

function firstMatch(text: string, pattern: RegExp): { index: number; text: string } | undefined {
  const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
  const clone = new RegExp(pattern.source, flags);
  const match = clone.exec(text);
  if (!match) return undefined;
  return { index: match.index, text: match[0].slice(0, 800) };
}

function lineNumberForIndex(text: string, index: number): number {
  return text.slice(0, index).split(/\r?\n/).length;
}

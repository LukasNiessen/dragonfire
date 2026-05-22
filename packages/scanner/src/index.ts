import {
  type Confidence,
  type Severity,
  type Signal,
  createSignal,
  normalizePath
} from "../../core/src/index.js";
import { type ArtifactSnapshot, type FileAsset, readFileText } from "../../ingest/src/index.js";
import type { MatcherProfile, StagePlan } from "../../stages/src/index.js";
import { createFrameworkSpecialistMatchers } from "./frameworks.js";

export interface MatcherMetadata {
  slug: string;
  name: string;
  category: string;
  severity: Severity;
  confidence: Confidence;
  noiseTier: "low" | "medium" | "high";
  frameworks?: string[];
  filePatterns?: string[];
  examples?: string[];
  provenance?: "proofstrike" | "security-surface-seed" | "community";
}

export interface MatcherPlugin extends MatcherMetadata {
  run(context: MatcherContext): Promise<Signal[]>;
}

export class MatcherRegistry {
  private readonly matchers = new Map<string, MatcherPlugin>();

  register(matcher: MatcherPlugin): void {
    if (!matcher.slug) throw new Error("Matcher must have a slug.");
    this.matchers.set(matcher.slug, matcher);
  }

  getAll(): MatcherPlugin[] {
    return [...this.matchers.values()];
  }

  get(slug: string): MatcherPlugin | undefined {
    return this.matchers.get(slug);
  }
}

export class MatcherEngine {
  constructor(private readonly registry = createDefaultMatcherRegistry()) {}

  async run(params: {
    snapshot: ArtifactSnapshot;
    stagePlan: Pick<StagePlan, "matcherProfile">;
    matcherSlugs?: string[];
    additionalMatchers?: MatcherPlugin[];
  }): Promise<Signal[]> {
    const selected = this.selectMatchers(params);
    const signals: Signal[] = [];
    const context = new MatcherContext(params.snapshot, params.stagePlan);
    for (const matcher of selected) {
      signals.push(...await matcher.run(context));
    }
    return signals.sort((a, b) => `${a.assetId}:${a.slug}`.localeCompare(`${b.assetId}:${b.slug}`));
  }

  selectMatchers(params: {
    snapshot: ArtifactSnapshot;
    stagePlan: Pick<StagePlan, "matcherProfile">;
    matcherSlugs?: string[];
    additionalMatchers?: MatcherPlugin[];
  }): MatcherPlugin[] {
    const allowedNoise = noiseTiersForProfile(params.stagePlan.matcherProfile);
    const requested = params.matcherSlugs?.length
      ? params.matcherSlugs.map((slug) => this.registry.get(slug)).filter((matcher): matcher is MatcherPlugin => Boolean(matcher))
      : uniqueMatchers([...this.registry.getAll(), ...(params.additionalMatchers ?? [])]);
    return requested.filter((matcher) => {
      if (!allowedNoise.includes(matcher.noiseTier)) return false;
      if (matcher.frameworks?.length) {
        const tags = params.snapshot.techProfile.tags;
        if (!matcher.frameworks.some((tag) => tags.includes(tag))) return false;
      }
      return true;
    });
  }
}

export class MatcherContext {
  readonly projectId: string;
  readonly runId: string;
  readonly rootPath: string;

  constructor(readonly snapshot: ArtifactSnapshot, readonly stagePlan: Pick<StagePlan, "matcherProfile">) {
    this.projectId = snapshot.projectId;
    this.runId = snapshot.runId;
    this.rootPath = snapshot.rootPath;
  }

  files({ languages = [] }: { languages?: string[] } = {}): FileAsset[] {
    return this.snapshot.files.filter((asset) => languages.length === 0 || languages.includes(asset.language));
  }

  readFile(filePath: string): string {
    return readFileText(this.rootPath, filePath);
  }

  signal(params: {
    asset: FileAsset;
    slug: string;
    confidence: Confidence;
    weight: number;
    lineNumbers: number[];
    snippet?: string;
    message: string;
    raw?: unknown;
    source?: string;
    kind?: "matcher_hit" | "negative_signal";
  }): Signal {
    return createSignal({
      runId: this.runId,
      projectId: this.projectId,
      assetId: params.asset.id,
      kind: params.kind ?? "matcher_hit",
      source: params.source ?? "proofstrike.builtins",
      slug: params.slug,
      confidence: params.confidence,
      weight: params.weight,
      lineNumbers: params.lineNumbers,
      snippet: params.snippet,
      message: params.message,
      raw: params.raw
    });
  }
}

export function createDefaultMatcherRegistry(): MatcherRegistry {
  const registry = new MatcherRegistry();
  for (const matcher of BUILTIN_MATCHERS) registry.register(matcher);
  return registry;
}

const EXPANDED_MATCHERS: MatcherPlugin[] = [
  regexMatcher({
    slug: "private-key-block",
    name: "Private key block in source",
    category: "secrets",
    severity: "critical",
    confidence: "high",
    noiseTier: "low",
    pattern: /-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/,
    message: "Private key material appears in source."
  }),
  regexMatcher({
    slug: "cloud-access-key",
    name: "Cloud provider access key",
    category: "secrets",
    severity: "critical",
    confidence: "high",
    noiseTier: "low",
    pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[A-Za-z0-9-]{10,}/,
    message: "Cloud or SaaS access key pattern appears in source."
  }),
  regexMatcher({
    slug: "database-url-with-credentials",
    name: "Database URL with embedded credentials",
    category: "secrets",
    severity: "high",
    confidence: "high",
    noiseTier: "low",
    pattern: /\b(?:postgres|postgresql|mysql|mongodb|redis):\/\/[^:\s"'`]+:[^@\s"'`]+@/i,
    message: "Connection string appears to embed credentials."
  }),
  regexMatcher({
    slug: "jwt-secret-hardcoded",
    name: "Hardcoded JWT secret",
    category: "auth",
    severity: "critical",
    confidence: "high",
    noiseTier: "low",
    pattern: /\b(?:jwtSecret|JWT_SECRET|signingSecret|tokenSecret)\b\s*[:=]\s*["'][^"']{12,}["']/,
    message: "JWT signing secret appears hardcoded."
  }),
  regexMatcher({
    slug: "oauth-state-missing",
    name: "OAuth callback without state verification",
    category: "auth",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:callback|oauth|authorize)\b[\s\S]{0,600}\b(?:code|authorization_code)\b/i,
    negativePattern: /\bstate\b[\s\S]{0,240}\b(?:verify|validate|compare|session|cookie)\b/i,
    message: "OAuth-like callback handles authorization code without obvious state validation."
  }),
  regexMatcher({
    slug: "csrf-disabled",
    name: "CSRF protection disabled",
    category: "auth",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:csrf|csurf|csrfProtection)\b[\s\S]{0,160}\b(?:false|disable|disabled|ignore)\b|csrf\s*:\s*false/i,
    message: "CSRF protection appears disabled."
  }),
  regexMatcher({
    slug: "password-hash-weak",
    name: "Weak password hashing",
    category: "crypto",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:md5|sha1)\s*\([^)]*(?:password|passwd|pwd)\b|\bcreateHash\s*\(\s*["'](?:md5|sha1)["']\s*\)[\s\S]{0,200}(?:password|passwd|pwd)/i,
    message: "Password-like value appears hashed with MD5/SHA1."
  }),
  regexMatcher({
    slug: "bcrypt-low-rounds",
    name: "bcrypt cost factor too low",
    category: "crypto",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bbcrypt\.(?:hash|genSalt)\s*\([^)]*,\s*(?:[0-7])\b/i,
    message: "bcrypt appears configured with a low cost factor."
  }),
  regexMatcher({
    slug: "pbkdf2-low-iterations",
    name: "PBKDF2 iteration count too low",
    category: "crypto",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bPBKDF2|pbkdf2(?:Sync)?\s*\([^)]*,\s*(?:[1-9]\d{0,3}|[1-4]\d{4})\b/i,
    message: "PBKDF2 appears to use a low iteration count."
  }),
  regexMatcher({
    slug: "static-iv",
    name: "Static initialization vector",
    category: "crypto",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:iv|nonce)\b\s*[:=]\s*(?:Buffer\.from\s*\(\s*)?["'][A-Za-z0-9+/=_-]{8,}["']/i,
    message: "Static IV/nonce appears configured for cryptographic operations."
  }),
  regexMatcher({
    slug: "tls-verification-disabled",
    name: "TLS certificate verification disabled",
    category: "crypto",
    severity: "high",
    confidence: "high",
    noiseTier: "low",
    pattern: /\brejectUnauthorized\s*:\s*false\b|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true/i,
    message: "TLS certificate verification appears disabled."
  }),
  regexMatcher({
    slug: "eval-user-input",
    name: "Dynamic code evaluation with user input",
    category: "rce",
    severity: "critical",
    confidence: "medium",
    noiseTier: "low",
    pattern: /\b(?:eval|Function|vm\.runIn(?:New)?Context)\s*\([^)]*(?:req\.|request\.|query|params|body|user|input)/is,
    message: "Dynamic code evaluation appears to use untrusted input."
  }),
  regexMatcher({
    slug: "python-eval-exec",
    name: "Python eval/exec usage",
    category: "rce",
    severity: "critical",
    confidence: "medium",
    noiseTier: "low",
    includeIf: (_text, asset) => asset.language === "python",
    pattern: /\b(?:eval|exec)\s*\([^)]*(?:request|input|args|form|json|query)/is,
    message: "Python eval/exec appears near request or user input."
  }),
  regexMatcher({
    slug: "php-eval-exec",
    name: "PHP eval or command execution",
    category: "rce",
    severity: "critical",
    confidence: "medium",
    noiseTier: "low",
    includeIf: (_text, asset) => asset.language === "php",
    pattern: /\b(?:eval|system|shell_exec|passthru|proc_open|popen)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/is,
    message: "PHP code or command execution appears to use request input."
  }),
  regexMatcher({
    slug: "ruby-command-exec",
    name: "Ruby command execution",
    category: "rce",
    severity: "critical",
    confidence: "medium",
    noiseTier: "low",
    includeIf: (_text, asset) => asset.language === "ruby",
    pattern: /\b(?:system|exec|spawn|Open3\.(?:capture|popen)|`[^`]*#\{params)/is,
    message: "Ruby command execution appears near params or interpolation."
  }),
  regexMatcher({
    slug: "go-command-exec",
    name: "Go command execution",
    category: "rce",
    severity: "critical",
    confidence: "medium",
    noiseTier: "low",
    includeIf: (_text, asset) => asset.language === "go",
    pattern: /\bexec\.Command\s*\([^)]*(?:r\.FormValue|r\.URL\.Query|http\.Request|os\.Args)/is,
    message: "Go command execution appears to use request or argument input."
  }),
  regexMatcher({
    slug: "template-injection",
    name: "Template rendering with untrusted template string",
    category: "injection",
    severity: "critical",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:render_template_string|Template\(|Handlebars\.compile|mustache\.render|ejs\.render)\s*\([^)]*(?:req\.|request|params|query|body|input)/is,
    message: "Template engine appears to compile or render user-controlled template content."
  }),
  regexMatcher({
    slug: "ldap-injection",
    name: "LDAP filter with interpolation",
    category: "injection",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:ldap|LDAP)[\s\S]{0,400}(?:search|filter)\s*[:=,(][\s\S]{0,300}(?:\+|\$\{|format\(|%s|f["'])/i,
    message: "LDAP filter appears to include interpolation or formatting."
  }),
  regexMatcher({
    slug: "xpath-injection",
    name: "XPath query with interpolation",
    category: "injection",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:xpath|XPath|selectNodes|SelectSingleNode)\b[\s\S]{0,300}(?:\+|\$\{|format\(|%s|f["'])/,
    message: "XPath query appears to include interpolation or formatting."
  }),
  regexMatcher({
    slug: "orm-order-by-injection",
    name: "ORM orderBy/sort from request input",
    category: "injection",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:orderBy|sort|order)\s*:\s*(?:req\.|request\.|query|params|body)|\.(?:orderBy|order)\s*\([^)]*(?:req\.|request\.|query|params|body)/is,
    message: "Sort/order field appears to be built from request input."
  }),
  regexMatcher({
    slug: "graphql-resolver-no-auth",
    name: "GraphQL mutation resolver without local auth signal",
    category: "auth",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:Mutation|mutation)\b[\s\S]{0,900}\b(?:resolve|resolver)\b/i,
    negativePattern: /\b(?:requireAuth|authorize|context\.user|ctx\.user|isAuthenticated|permission|role|guard)\b/i,
    message: "GraphQL mutation resolver has no obvious local auth or authorization signal."
  }),
  regexMatcher({
    slug: "trpc-public-procedure",
    name: "tRPC public procedure with mutation",
    category: "auth",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bpublicProcedure\b[\s\S]{0,700}\bmutation\s*\(/,
    message: "tRPC public mutation should be reviewed for authentication and authorization."
  }),
  regexMatcher({
    slug: "nextjs-server-action-no-auth",
    name: "Next.js server action without local auth signal",
    category: "auth",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /["']use server["'][\s\S]{0,1000}\b(?:export\s+async\s+function|async\s+function)\b/i,
    negativePattern: /\b(?:auth|currentUser|getServerSession|requireUser|requireAuth|authorize|permission|role)\b/i,
    message: "Next.js server action has no obvious local auth or authorization signal."
  }),
  regexMatcher({
    slug: "fastapi-route-no-auth",
    name: "FastAPI route without dependency auth",
    category: "auth",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.language === "python",
    pattern: /@(?:app|router)\.(?:get|post|put|patch|delete)\s*\(/,
    negativePattern: /\b(?:Depends|Security|OAuth2|current_user|require_user|permission|role)\b/i,
    message: "FastAPI route has no obvious dependency-based auth or authorization signal."
  }),
  regexMatcher({
    slug: "flask-route-no-auth",
    name: "Flask route without auth decorator",
    category: "auth",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.language === "python",
    pattern: /@(?:app|blueprint|bp)\.route\s*\(/,
    negativePattern: /\b(?:login_required|jwt_required|current_user|permission|role|require_user)\b/i,
    message: "Flask route has no obvious authentication decorator or authorization check."
  }),
  regexMatcher({
    slug: "django-view-no-auth",
    name: "Django view without auth decorator or mixin",
    category: "auth",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.language === "python",
    pattern: /\b(?:class\s+\w+View|def\s+\w+\s*\(\s*request)/,
    negativePattern: /\b(?:login_required|permission_required|LoginRequiredMixin|PermissionRequiredMixin|request\.user\.is_authenticated)\b/i,
    message: "Django view has no obvious auth decorator, mixin, or user check."
  }),
  regexMatcher({
    slug: "rails-controller-no-auth",
    name: "Rails controller without before_action auth",
    category: "auth",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.language === "ruby",
    pattern: /class\s+\w+Controller\s*<\s*ApplicationController/i,
    negativePattern: /\bbefore_action\s+:(?:authenticate|authorize|require|current_user)|\bauthorize\b/i,
    message: "Rails controller has no obvious authentication or authorization before_action."
  }),
  regexMatcher({
    slug: "laravel-route-no-middleware",
    name: "Laravel route without auth middleware",
    category: "auth",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.language === "php",
    pattern: /\bRoute::(?:get|post|put|patch|delete|resource)\s*\(/,
    negativePattern: /\bmiddleware\s*\(\s*["'](?:auth|can|verified)|authorize\(|Gate::/i,
    message: "Laravel route has no obvious auth/can middleware or authorization check."
  }),
  regexMatcher({
    slug: "spring-controller-no-preauthorize",
    name: "Spring controller without method authorization",
    category: "auth",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.language === "java",
    pattern: /@(RestController|Controller)[\s\S]{0,1200}@(?:GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping)/,
    negativePattern: /@(?:PreAuthorize|PostAuthorize|Secured|RolesAllowed)|SecurityContext|Principal\b/,
    message: "Spring controller route has no obvious method authorization signal."
  }),
  regexMatcher({
    slug: "dotnet-controller-allowanonymous",
    name: "ASP.NET controller allows anonymous access",
    category: "auth",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.language === "csharp",
    pattern: /\[AllowAnonymous\][\s\S]{0,500}\[(?:HttpGet|HttpPost|HttpPut|HttpPatch|HttpDelete|Route)\]/,
    message: "ASP.NET route explicitly allows anonymous access."
  }),
  regexMatcher({
    slug: "py-sql-raw",
    name: "Python raw SQL with interpolation",
    category: "injection",
    severity: "high",
    confidence: "medium",
    noiseTier: "low",
    includeIf: (_text, asset) => asset.language === "python",
    pattern: /\b(?:execute|executemany)\s*\([^)]*(?:f["']|%|\.format\(|\+)/is,
    message: "Python SQL execution appears to use string interpolation or formatting."
  }),
  regexMatcher({
    slug: "go-sql-raw",
    name: "Go raw SQL with formatting",
    category: "injection",
    severity: "high",
    confidence: "medium",
    noiseTier: "low",
    includeIf: (_text, asset) => asset.language === "go",
    pattern: /\b(?:db|tx)\.(?:Query|QueryRow|Exec)\s*\([^)]*(?:fmt\.Sprintf|\+)/is,
    message: "Go SQL execution appears to use formatting or string concatenation."
  }),
  regexMatcher({
    slug: "php-sql-raw",
    name: "PHP raw SQL with request interpolation",
    category: "injection",
    severity: "high",
    confidence: "medium",
    noiseTier: "low",
    includeIf: (_text, asset) => asset.language === "php",
    pattern: /\b(?:query|exec|prepare)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/is,
    message: "PHP SQL execution appears to include request data."
  }),
  regexMatcher({
    slug: "ruby-sql-raw",
    name: "Ruby raw SQL with interpolation",
    category: "injection",
    severity: "high",
    confidence: "medium",
    noiseTier: "low",
    includeIf: (_text, asset) => asset.language === "ruby",
    pattern: /\b(?:find_by_sql|execute|where)\s*\([^)]*(?:#\{|params\[|\+)/is,
    message: "Ruby SQL/query construction appears to include params or interpolation."
  }),
  regexMatcher({
    slug: "jvm-sql-raw",
    name: "JVM raw SQL with concatenation",
    category: "injection",
    severity: "high",
    confidence: "medium",
    noiseTier: "low",
    pattern: /\b(?:createStatement|executeQuery|executeUpdate|jdbcTemplate\.query)\s*\([^;]*(?:\+\s*(?:request|param|input|user)|String\.format)/is,
    message: "JVM SQL execution appears to use concatenation or formatting."
  }),
  regexMatcher({
    slug: "dotnet-sql-raw",
    name: ".NET raw SQL with interpolation",
    category: "injection",
    severity: "high",
    confidence: "medium",
    noiseTier: "low",
    includeIf: (_text, asset) => asset.language === "csharp",
    pattern: /\b(?:SqlCommand|FromSqlRaw|ExecuteSqlRaw)\s*\([^)]*(?:\$"|string\.Format|\+)/is,
    message: ".NET SQL execution appears to use interpolation or string formatting."
  }),
  regexMatcher({
    slug: "zip-slip",
    name: "Archive extraction path traversal",
    category: "path-traversal",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:ZipEntry|zipfile|adm-zip|extractall|tar\.extract|entry\.path)\b[\s\S]{0,700}\b(?:writeFile|createWriteStream|extract|join)\b/i,
    negativePattern: /\b(?:normalize|resolve|realpath|safeJoin|startsWith)\b/i,
    message: "Archive extraction path appears to be written without obvious traversal containment."
  }),
  regexMatcher({
    slug: "path-join-user-input",
    name: "Path join with request input",
    category: "path-traversal",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bpath\.(?:join|resolve)\s*\([^)]*(?:req\.|request\.|query|params|body|userInput|filename)/is,
    negativePattern: /\b(?:basename|normalize|safeJoin|allowlist|startsWith)\b/i,
    message: "Filesystem path construction appears to include request input."
  }),
  regexMatcher({
    slug: "redirect-allowlist-regex-only",
    name: "Redirect allowlist uses weak regex",
    category: "open-redirect",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:redirect|returnTo|nextUrl|callbackUrl)\b[\s\S]{0,600}\b(?:RegExp|\.test\s*\(|match\s*\()/i,
    negativePattern: /\b(?:new URL|URLPattern|hostname|origin)\b/i,
    message: "Redirect allowlist appears regex-only; verify URL parsing and origin checks."
  }),
  regexMatcher({
    slug: "ssrf-metadata-service",
    name: "Cloud metadata service reachable from server request",
    category: "ssrf",
    severity: "critical",
    confidence: "high",
    noiseTier: "low",
    pattern: /169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2|instance-data/i,
    message: "Server-side request code references a cloud metadata endpoint."
  }),
  regexMatcher({
    slug: "url-validation-regex-only",
    name: "URL validation by regex only",
    category: "ssrf",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:url|uri|callback|webhook)\b[\s\S]{0,300}\b(?:RegExp|\.test\s*\(|match\s*\()/i,
    negativePattern: /\b(?:new URL|parse_url|urlparse|URI\.parse|net\.SplitHostPort|ipaddr|isPrivate)\b/i,
    message: "URL validation appears regex-based without structured parsing or private-address checks."
  }),
  regexMatcher({
    slug: "react-unsafe-json-in-html",
    name: "JSON embedded into HTML without escaping",
    category: "xss",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bJSON\.stringify\s*\([^)]*(?:req\.|props|data|user)[\s\S]{0,400}(?:dangerouslySetInnerHTML|<script|innerHTML)/i,
    message: "JSON appears embedded into HTML/script context without obvious escaping."
  }),
  regexMatcher({
    slug: "angular-bypass-security-trust",
    name: "Angular sanitizer bypass",
    category: "xss",
    severity: "high",
    confidence: "high",
    noiseTier: "low",
    pattern: /\bbypassSecurityTrust(?:Html|Url|ResourceUrl|Script|Style)\s*\(/,
    message: "Angular DomSanitizer bypass API is used."
  }),
  regexMatcher({
    slug: "markdown-raw-html",
    name: "Markdown rendered with raw HTML enabled",
    category: "xss",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:rehypeRaw|allowDangerousHtml|html\s*:\s*true|sanitize\s*:\s*false)\b/i,
    message: "Markdown/HTML renderer appears to allow raw HTML or disable sanitization."
  }),
  regexMatcher({
    slug: "postmessage-no-origin-check",
    name: "postMessage listener without origin check",
    category: "xss",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /addEventListener\s*\(\s*["']message["'][\s\S]{0,800}\bevent\.data\b/i,
    negativePattern: /\bevent\.origin\b[\s\S]{0,250}(?:===|includes|allowlist|trusted)/i,
    message: "postMessage listener reads event data without an obvious origin check."
  }),
  regexMatcher({
    slug: "response-header-leak",
    name: "Sensitive response header leak",
    category: "exposure",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:setHeader|header)\s*\([^)]*(?:Authorization|Cookie|Set-Cookie|X-Api-Key|Token|Secret)/i,
    message: "Sensitive header value appears to be reflected or set in a response."
  }),
  regexMatcher({
    slug: "debug-mode-enabled",
    name: "Debug mode enabled",
    category: "exposure",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:debug|DEBUG|app\.debug|FLASK_DEBUG|DJANGO_DEBUG|spring\.debug)\b\s*[:=]\s*(?:true|1|["']true["'])/i,
    message: "Debug mode appears enabled in source or config."
  }),
  regexMatcher({
    slug: "stacktrace-response",
    name: "Stack trace returned to response",
    category: "exposure",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:stack|stackTrace|traceback|err\.stack|exception)\b[\s\S]{0,250}\b(?:res\.send|res\.json|Response\.json|render)/i,
    message: "Stack trace or exception detail appears returned to clients."
  }),
  regexMatcher({
    slug: "rate-limit-missing-login",
    name: "Login route without local rate limit signal",
    category: "auth",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:app|router)\.post\s*\(\s*["'`][^"'`]*(?:login|signin|auth|password-reset)/i,
    negativePattern: /\b(?:rateLimit|throttle|limiter|slowDown|brute|attempts|captcha)\b/i,
    message: "Authentication route has no obvious local rate limiting or brute-force protection signal."
  }),
  regexMatcher({
    slug: "webhook-replay-missing",
    name: "Webhook signature without replay check",
    category: "auth",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (text, asset) => /webhook/i.test(asset.filePath) || /webhook/i.test(text),
    pattern: /\b(?:signature|hmac|constructEvent|verify)\b/i,
    negativePattern: /\b(?:timestamp|tolerance|replay|nonce|idempotency)\b/i,
    message: "Webhook signature verification appears present, but no obvious replay/timestamp check was found."
  }),
  regexMatcher({
    slug: "email-html-injection",
    name: "HTML email rendered from user content",
    category: "xss",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:sendMail|mail|email)\s*\([^)]*(?:html\s*:)[\s\S]{0,400}(?:req\.|request\.|body|user|message|comment)/is,
    negativePattern: /\b(?:escape|sanitize|DOMPurify|he|encode)\b/i,
    message: "HTML email body appears to include user content without obvious escaping."
  }),
  regexMatcher({
    slug: "model-output-to-sql",
    name: "Model output used in database query",
    category: "ai-appsec",
    severity: "critical",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:completion|modelOutput|assistantMessage|llmResponse)\b[\s\S]{0,700}\b(?:query|execute|raw|sql)\s*\(/i,
    message: "Model output appears to flow into a database query."
  }),
  regexMatcher({
    slug: "model-output-to-shell",
    name: "Model output used in shell command",
    category: "ai-appsec",
    severity: "critical",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:completion|modelOutput|assistantMessage|llmResponse)\b[\s\S]{0,700}\b(?:exec|spawn|system|subprocess)\s*\(/i,
    message: "Model output appears to flow into command execution."
  }),
  regexMatcher({
    slug: "tool-schema-missing",
    name: "AI tool without argument schema",
    category: "ai-appsec",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:tool|functionTool|registerTool|server\.tool)\s*\([^)]*(?:delete|admin|payment|email|database|execute)/is,
    negativePattern: /\b(?:schema|inputSchema|parameters|z\.object|jsonSchema|argsSchema)\b/i,
    message: "Privileged AI tool appears to lack an obvious argument schema."
  }),
  regexMatcher({
    slug: "rag-untrusted-html",
    name: "RAG ingestion of untrusted HTML",
    category: "ai-appsec",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:cheerio|JSDOM|parseHTML|htmlToText|crawler|scrape)\b[\s\S]{0,800}\b(?:embed|vector|upsert|retriev)/i,
    negativePattern: /\b(?:sanitize|strip|allowlist|trustedDomain|contentPolicy)\b/i,
    message: "RAG pipeline appears to ingest HTML/web content without obvious sanitization or trust filtering."
  }),
  regexMatcher({
    slug: "prompt-leak-debug-route",
    name: "Prompt or messages exposed through debug route",
    category: "ai-appsec",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:prompt|system|developer|messages|transcript)\b[\s\S]{0,600}\b(?:debug|dump|trace|res\.json|Response\.json)\b/i,
    message: "Prompt, transcript, or model messages appear near a debug/response sink."
  }),
  regexMatcher({
    slug: "github-oidc-wildcard-subject",
    name: "GitHub OIDC trust policy wildcard",
    category: "ci-cd",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /token\.actions\.githubusercontent\.com[\s\S]{0,700}(?:repo:\*|repo:[^"']+:\*)/i,
    message: "GitHub OIDC trust condition appears overly broad."
  }),
  regexMatcher({
    slug: "github-workflow-untrusted-checkout",
    name: "Privileged workflow checks out untrusted PR head",
    category: "ci-cd",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.filePath.includes(".github/workflows/"),
    pattern: /pull_request_target[\s\S]{0,1500}actions\/checkout[\s\S]{0,500}(?:github\.event\.pull_request\.head|head\.sha)/i,
    message: "pull_request_target workflow appears to check out untrusted PR head code."
  }),
  regexMatcher({
    slug: "ci-secret-echo",
    name: "CI workflow echoes secret-like value",
    category: "ci-cd",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.filePath.includes(".github/workflows/"),
    pattern: /\b(?:echo|printf)\b[^\n]*(?:secrets\.|TOKEN|PASSWORD|PRIVATE|KEY)/i,
    message: "Workflow step appears to echo or print secret-like values."
  }),
  regexMatcher({
    slug: "ci-curl-pipe-shell",
    name: "CI pipes remote script to shell",
    category: "ci-cd",
    severity: "high",
    confidence: "medium",
    noiseTier: "low",
    pattern: /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sh|bash|pwsh|powershell)\b/i,
    message: "CI or script code pipes remote content into a shell."
  }),
  regexMatcher({
    slug: "package-insecure-registry",
    name: "Insecure package registry",
    category: "supply-chain",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bregistry\s*=\s*http:\/\/|npmRegistryServer:\s*["']http:\/\/|PIP_INDEX_URL\s*=\s*http:\/\//i,
    message: "Package manager registry appears to use plaintext HTTP."
  }),
  regexMatcher({
    slug: "package-unpinned-git-dependency",
    name: "Unpinned git dependency",
    category: "supply-chain",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.filePath.endsWith("package.json"),
    pattern: /"[^"]+"\s*:\s*"git\+(?:https|ssh):\/\/[^"#]+(?:#(?:main|master|develop|HEAD))?"/i,
    message: "Dependency is sourced from git without an immutable commit pin."
  }),
  regexMatcher({
    slug: "dockerfile-latest-tag",
    name: "Dockerfile uses mutable latest tag",
    category: "container",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.language === "dockerfile",
    pattern: /^FROM\s+\S+:latest\b|^FROM\s+[^\s:@]+$/im,
    message: "Dockerfile base image appears mutable or unpinned."
  }),
  regexMatcher({
    slug: "dockerfile-add-remote-url",
    name: "Dockerfile ADD remote URL",
    category: "container",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.language === "dockerfile",
    pattern: /^ADD\s+https?:\/\//im,
    message: "Dockerfile ADD downloads remote content during build."
  }),
  regexMatcher({
    slug: "dockerfile-secret-env",
    name: "Dockerfile secret in ENV",
    category: "container",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.language === "dockerfile",
    pattern: /^ENV\s+\w*(?:SECRET|TOKEN|PASSWORD|PRIVATE|KEY)\w*\s*=\s*\S+/im,
    message: "Dockerfile ENV appears to bake a secret-like value into an image."
  }),
  regexMatcher({
    slug: "kubernetes-hostpath-mount",
    name: "Kubernetes hostPath mount",
    category: "iac",
    severity: "high",
    confidence: "high",
    noiseTier: "low",
    includeIf: (_text, asset) => asset.language === "yaml",
    pattern: /\bhostPath\s*:/i,
    message: "Kubernetes workload mounts a hostPath volume."
  }),
  regexMatcher({
    slug: "kubernetes-run-as-root",
    name: "Kubernetes container may run as root",
    category: "iac",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.language === "yaml",
    pattern: /\b(?:runAsUser\s*:\s*0|runAsNonRoot\s*:\s*false|allowPrivilegeEscalation\s*:\s*true)\b/i,
    message: "Kubernetes security context appears to allow root or privilege escalation."
  }),
  regexMatcher({
    slug: "kubernetes-secret-env",
    name: "Kubernetes secret exposed as environment variable",
    category: "iac",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.language === "yaml",
    pattern: /\bsecretKeyRef\s*:/i,
    message: "Kubernetes secret is exposed to the container environment; verify least privilege and logging hygiene."
  }),
  regexMatcher({
    slug: "terraform-s3-public",
    name: "Terraform S3 public access",
    category: "iac",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.filePath.endsWith(".tf"),
    pattern: /\b(?:acl\s*=\s*["']public-read|block_public_acls\s*=\s*false|block_public_policy\s*=\s*false|ignore_public_acls\s*=\s*false|restrict_public_buckets\s*=\s*false)\b/i,
    message: "Terraform S3 configuration appears to allow public access."
  }),
  regexMatcher({
    slug: "terraform-unencrypted-storage",
    name: "Terraform storage encryption disabled or missing",
    category: "iac",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.filePath.endsWith(".tf"),
    pattern: /\b(?:server_side_encryption_configuration|storage_encrypted|encrypted)\s*=\s*false\b|resource\s+["']aws_(?:db_instance|ebs_volume|s3_bucket)["']/i,
    message: "Terraform storage resource needs encryption review."
  }),
  regexMatcher({
    slug: "terraform-secret-in-data",
    name: "Terraform secret value in configuration",
    category: "iac",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.filePath.endsWith(".tf"),
    pattern: /\b(?:password|secret|token|private_key)\s*=\s*["'][^"']{8,}["']/i,
    message: "Terraform configuration appears to contain secret material."
  }),
  regexMatcher({
    slug: "terraform-unpinned-module",
    name: "Terraform module without immutable ref",
    category: "iac",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.filePath.endsWith(".tf"),
    pattern: /\bsource\s*=\s*["']git::[^"']+["']/i,
    negativePattern: /\?ref=[0-9a-f]{40}\b/i,
    message: "Terraform git module source is not pinned to an immutable commit SHA."
  }),
  regexMatcher({
    slug: "android-exported-activity",
    name: "Android exported component",
    category: "mobile",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /android:exported\s*=\s*["']true["']/i,
    message: "Android component is exported; verify permission and intent validation."
  }),
  regexMatcher({
    slug: "ios-insecure-webview",
    name: "iOS WebView risky configuration",
    category: "mobile",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:WKWebView|UIWebView)\b[\s\S]{0,800}\b(?:javaScriptEnabled\s*=\s*true|allowsInlineMediaPlayback|loadHTMLString)\b/i,
    message: "iOS WebView configuration needs review for untrusted content and bridge exposure."
  })
];

const PRODUCT_GRADE_MATCHERS: MatcherPlugin[] = [
  regexMatcher({
    slug: "secret-npm-token",
    name: "NPM token in source",
    category: "secrets",
    severity: "critical",
    confidence: "high",
    noiseTier: "low",
    pattern: /\bnpm_[A-Za-z0-9]{24,}\b/,
    message: "NPM access token pattern appears in source."
  }),
  regexMatcher({
    slug: "secret-github-token",
    name: "GitHub token in source",
    category: "secrets",
    severity: "critical",
    confidence: "high",
    noiseTier: "low",
    pattern: /\bgh[pousr]_[A-Za-z0-9_]{30,}\b|github_pat_[A-Za-z0-9_]{40,}/,
    message: "GitHub token pattern appears in source."
  }),
  regexMatcher({
    slug: "secret-stripe-key",
    name: "Stripe secret key in source",
    category: "secrets",
    severity: "critical",
    confidence: "high",
    noiseTier: "low",
    pattern: /\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b/,
    message: "Stripe secret key pattern appears in source."
  }),
  regexMatcher({
    slug: "secret-sendgrid-key",
    name: "SendGrid API key in source",
    category: "secrets",
    severity: "critical",
    confidence: "high",
    noiseTier: "low",
    pattern: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/,
    message: "SendGrid API key pattern appears in source."
  }),
  regexMatcher({
    slug: "secret-twilio-token",
    name: "Twilio credential in source",
    category: "secrets",
    severity: "critical",
    confidence: "high",
    noiseTier: "low",
    pattern: /\bAC[a-f0-9]{32}\b[\s\S]{0,240}\b(?:authToken|TWILIO_AUTH_TOKEN)\b\s*[:=]\s*["'][^"']{16,}["']/i,
    message: "Twilio account SID appears near a hardcoded auth token."
  }),
  regexMatcher({
    slug: "secret-slack-webhook-url",
    name: "Slack webhook URL in source",
    category: "secrets",
    severity: "critical",
    confidence: "high",
    noiseTier: "low",
    pattern: /https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[A-Za-z0-9]+/,
    message: "Slack incoming webhook URL appears in source."
  }),
  regexMatcher({
    slug: "secret-basic-auth-url",
    name: "Basic auth credentials in URL",
    category: "secrets",
    severity: "high",
    confidence: "high",
    noiseTier: "low",
    pattern: /https?:\/\/[^:\s"'`/]+:[^@\s"'`/]+@[^/\s"'`]+/i,
    message: "URL appears to embed basic-auth credentials."
  }),
  regexMatcher({
    slug: "secret-aws-session-token",
    name: "AWS session token in source",
    category: "secrets",
    severity: "critical",
    confidence: "medium",
    noiseTier: "low",
    pattern: /\bAWS_SESSION_TOKEN\b\s*[:=]\s*["'][A-Za-z0-9/+=]{40,}["']/,
    message: "AWS session token appears hardcoded."
  }),
  regexMatcher({
    slug: "secret-gcp-service-account-json",
    name: "GCP service account key in source",
    category: "secrets",
    severity: "critical",
    confidence: "high",
    noiseTier: "low",
    pattern: /"type"\s*:\s*"service_account"[\s\S]{0,1200}"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----/i,
    message: "GCP service account private key JSON appears in source."
  }),
  regexMatcher({
    slug: "secret-azure-storage-key",
    name: "Azure storage account key in source",
    category: "secrets",
    severity: "critical",
    confidence: "medium",
    noiseTier: "low",
    pattern: /\bAccountKey=[A-Za-z0-9+/=]{40,}\b/i,
    message: "Azure storage account key appears in source."
  }),
  regexMatcher({
    slug: "secret-kubeconfig-client-key",
    name: "Kubeconfig client key in source",
    category: "secrets",
    severity: "critical",
    confidence: "high",
    noiseTier: "low",
    pattern: /\bclient-key-data\s*:\s*[A-Za-z0-9+/=]{80,}/,
    message: "Kubernetes client key material appears in source."
  }),
  regexMatcher({
    slug: "secret-docker-auth-config",
    name: "Docker registry auth in source",
    category: "secrets",
    severity: "critical",
    confidence: "medium",
    noiseTier: "low",
    pattern: /"auths"\s*:\s*\{[\s\S]{0,800}"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"/,
    message: "Docker registry auth config appears in source."
  }),
  regexMatcher({
    slug: "secret-terraform-variable-default",
    name: "Terraform secret variable default",
    category: "secrets",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.filePath.endsWith(".tf"),
    pattern: /variable\s+"[^"]*(?:password|secret|token|key)[^"]*"[\s\S]{0,300}default\s*=\s*"[^"]{8,}"/i,
    message: "Terraform secret-like variable defines a hardcoded default."
  }),
  regexMatcher({
    slug: "secret-pem-passphrase",
    name: "PEM passphrase in source",
    category: "secrets",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:PEM_PASSPHRASE|KEY_PASSPHRASE|PRIVATE_KEY_PASSWORD)\b\s*[:=]\s*["'][^"']{8,}["']/i,
    message: "Private-key passphrase appears hardcoded."
  }),
  regexMatcher({
    slug: "secret-sentry-dsn",
    name: "Sentry DSN in source",
    category: "secrets",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /https:\/\/[a-f0-9]{16,}@[A-Za-z0-9.-]+\/\d+/i,
    message: "Sentry-like DSN appears in source; verify whether it exposes sensitive project telemetry."
  }),
  regexMatcher({
    slug: "secret-database-password-env-default",
    name: "Database password fallback",
    category: "secrets",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:DB_PASSWORD|DATABASE_PASSWORD|PGPASSWORD)\b[\s\S]{0,120}(?:\|\||\?\?)\s*["'][^"']{6,}["']/,
    message: "Database password environment variable has a hardcoded fallback."
  }),
  regexMatcher({
    slug: "session-cookie-secure-false",
    name: "Session cookie Secure disabled",
    category: "auth",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:secure|cookieSecure)\s*:\s*false\b|set_cookie\([^)]*secure\s*=\s*False/i,
    message: "Session or auth cookie appears to disable the Secure flag."
  }),
  regexMatcher({
    slug: "session-cookie-http-only-false",
    name: "Session cookie HttpOnly disabled",
    category: "auth",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:httpOnly|httponly)\s*:\s*false\b|set_cookie\([^)]*httponly\s*=\s*False/i,
    message: "Session or auth cookie appears to disable HttpOnly."
  }),
  regexMatcher({
    slug: "express-session-default-secret",
    name: "Express session default secret",
    category: "auth",
    severity: "critical",
    confidence: "high",
    noiseTier: "low",
    pattern: /\bsession\s*\(\s*\{[\s\S]{0,400}\bsecret\s*:\s*["'](?:secret|keyboard cat|changeme|password|dev)["']/i,
    message: "Express session appears configured with a default or weak static secret."
  }),
  regexMatcher({
    slug: "passport-serialize-user-full-object",
    name: "Passport serializes full user object",
    category: "auth",
    severity: "medium",
    confidence: "medium",
    noiseTier: "high",
    pattern: /serializeUser\s*\([^)]*=>\s*done\s*\(\s*null\s*,\s*user\s*\)|serializeUser\s*\([^)]*done\s*\(\s*null\s*,\s*user\s*\)/i,
    message: "Passport serializeUser appears to store the full user object in session."
  }),
  regexMatcher({
    slug: "jwt-ignore-expiration",
    name: "JWT expiration ignored",
    category: "auth",
    severity: "high",
    confidence: "high",
    noiseTier: "low",
    pattern: /\bignoreExpiration\s*:\s*true\b|verify_exp\s*:\s*false\b/i,
    message: "JWT verification appears to ignore expiration."
  }),
  regexMatcher({
    slug: "jwt-none-algorithm-allowed",
    name: "JWT none algorithm allowed",
    category: "auth",
    severity: "critical",
    confidence: "high",
    noiseTier: "low",
    pattern: /\balgorithms?\s*:\s*\[[^\]]*["']none["']|algorithm\s*=\s*["']none["']/i,
    message: "JWT verification appears to allow the none algorithm."
  }),
  regexMatcher({
    slug: "jwt-verify-without-algorithms",
    name: "JWT verify without algorithm allowlist",
    category: "auth",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bjwt\.verify\s*\([^)]{0,240}\)/i,
    negativePattern: /\b(?:algorithms|issuer|audience)\s*:/i,
    message: "JWT verification has no obvious algorithm/issuer/audience constraints."
  }),
  regexMatcher({
    slug: "oauth-redirect-uri-wildcard",
    name: "OAuth redirect URI wildcard",
    category: "auth",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bredirect_?uri\b[\s\S]{0,240}(?:\*|startsWith\s*\(|includes\s*\()/i,
    message: "OAuth redirect URI validation appears wildcarded or prefix-based."
  }),
  regexMatcher({
    slug: "saml-want-assertions-signed-false",
    name: "SAML assertion signature disabled",
    category: "auth",
    severity: "critical",
    confidence: "high",
    noiseTier: "low",
    pattern: /\b(?:wantAssertionsSigned|wantAuthnResponseSigned|validateInResponseTo)\b\s*[:=]\s*false\b/i,
    message: "SAML assertion or response validation appears disabled."
  }),
  regexMatcher({
    slug: "ldap-anonymous-bind",
    name: "LDAP anonymous bind",
    category: "auth",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:ldap|client)\.bind\s*\(\s*["']{2}\s*,\s*["']{2}|simple_bind_s\s*\(\s*["']{2}\s*,\s*["']{2}/i,
    message: "LDAP client appears to bind anonymously."
  }),
  regexMatcher({
    slug: "api-key-query-param",
    name: "API key read from query string",
    category: "auth",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:req|request)\.query\.(?:api[_-]?key|token|access[_-]?token)\b|\bparams\[[\"'](?:api[_-]?key|token|access[_-]?token)[\"']\]/i,
    message: "API key or token appears to be accepted from a URL query parameter."
  }),
  regexMatcher({
    slug: "admin-role-client-controlled",
    name: "Admin role trusted from request input",
    category: "auth",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:req|request)\.(?:body|query|params)\.(?:role|isAdmin|admin)[\s\S]{0,160}(?:admin|isAdmin|role)|\b(?:role|isAdmin)\s*=\s*(?:req|request)\.(?:body|query|params)\./i,
    message: "Authorization decision appears to trust role/admin data from client-controlled input."
  }),
  regexMatcher({
    slug: "tenant-filter-missing",
    name: "Tenant-scoped query missing tenant predicate",
    category: "authorization",
    severity: "high",
    confidence: "low",
    noiseTier: "high",
    pattern: /\b(?:findMany|findAll|select|query)\s*\([\s\S]{0,500}\b(?:orgId|tenantId|workspaceId|accountId)\b/i,
    negativePattern: /\bwhere\b[\s\S]{0,240}\b(?:orgId|tenantId|workspaceId|accountId)\b/i,
    message: "Multi-tenant-looking query has no obvious tenant predicate nearby."
  }),
  regexMatcher({
    slug: "node-child-process-user-input",
    name: "Node child process receives user input",
    category: "rce",
    severity: "critical",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:exec|execSync|spawn|spawnSync)\s*\([^)]*(?:req\.|request\.|params|query|body|argv|process\.env)/i,
    message: "Child process execution appears to consume user-controlled input."
  }),
  regexMatcher({
    slug: "node-vm-runincontext-user-input",
    name: "Node VM executes user input",
    category: "rce",
    severity: "critical",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:runInNewContext|runInContext|vm\.Script)\s*\([^)]*(?:req\.|request\.|params|query|body)/i,
    message: "Node VM execution appears to consume user-controlled input."
  }),
  regexMatcher({
    slug: "java-runtime-exec-user-input",
    name: "Java Runtime exec receives user input",
    category: "rce",
    severity: "critical",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bRuntime\.getRuntime\(\)\.exec\s*\([^)]*(?:request|getParameter|param|args)/i,
    message: "Java Runtime.exec appears to consume user-controlled input."
  }),
  regexMatcher({
    slug: "python-subprocess-shell-true",
    name: "Python subprocess shell=True with input",
    category: "rce",
    severity: "critical",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bsubprocess\.(?:run|call|Popen|check_output)\s*\([\s\S]{0,300}shell\s*=\s*True/i,
    message: "Python subprocess uses shell=True; verify command construction is not user-controlled."
  }),
  regexMatcher({
    slug: "python-pickle-loads-request",
    name: "Python pickle loads request data",
    category: "deserialization",
    severity: "critical",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bpickle\.loads?\s*\([^)]*(?:request|flask\.request|body|data|payload|input)/i,
    message: "pickle appears to deserialize request or payload data."
  }),
  regexMatcher({
    slug: "python-yaml-unsafe-load",
    name: "Python unsafe YAML load",
    category: "deserialization",
    severity: "high",
    confidence: "high",
    noiseTier: "low",
    pattern: /\byaml\.load\s*\([^)]*\)/i,
    negativePattern: /\b(?:SafeLoader|safe_load)\b/i,
    message: "yaml.load is used without an obvious safe loader."
  }),
  regexMatcher({
    slug: "java-objectinputstream",
    name: "Java ObjectInputStream deserialization",
    category: "deserialization",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bnew\s+ObjectInputStream\s*\(|\.readObject\s*\(/,
    message: "Java native deserialization surface appears in source."
  }),
  regexMatcher({
    slug: "dotnet-binaryformatter",
    name: ".NET BinaryFormatter usage",
    category: "deserialization",
    severity: "critical",
    confidence: "high",
    noiseTier: "low",
    pattern: /\bBinaryFormatter\b|NetDataContractSerializer\b/,
    message: ".NET insecure deserialization API appears in source."
  }),
  regexMatcher({
    slug: "php-unserialize-user-input",
    name: "PHP unserialize receives user input",
    category: "deserialization",
    severity: "critical",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bunserialize\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)/i,
    message: "PHP unserialize appears to consume user-controlled input."
  }),
  regexMatcher({
    slug: "ruby-marshal-load-user-input",
    name: "Ruby Marshal load receives input",
    category: "deserialization",
    severity: "critical",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bMarshal\.load\s*\([^)]*(?:params|request|cookies|env)/i,
    message: "Ruby Marshal.load appears to consume request-controlled input."
  }),
  regexMatcher({
    slug: "go-template-user-defined",
    name: "Go template parsed from user input",
    category: "injection",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\btemplate\.(?:New|Must)\([^)]*\)[\s\S]{0,240}\.Parse\s*\([^)]*(?:r\.Form|r\.URL|request|param|query)/i,
    message: "Go template parsing appears to use user-controlled template text."
  }),
  regexMatcher({
    slug: "rust-command-user-input",
    name: "Rust command receives user input",
    category: "rce",
    severity: "critical",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bCommand::new\s*\([^)]*(?:env::args|query|params|request|body)/i,
    message: "Rust Command execution appears to consume user-controlled input."
  }),
  regexMatcher({
    slug: "mongodb-where-user-input",
    name: "MongoDB $where user input",
    category: "injection",
    severity: "critical",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\$where\s*:\s*(?:req\.|request\.|params|query|body)|where\s*\([^)]*(?:req\.|request\.|params|query|body)/i,
    message: "MongoDB $where-style query appears to consume user-controlled input."
  }),
  regexMatcher({
    slug: "elasticsearch-query-string-user-input",
    name: "Elasticsearch query_string user input",
    category: "injection",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bquery_string\b[\s\S]{0,300}\b(?:req\.|request\.|params|query|body|input)\b/i,
    message: "Elasticsearch query_string appears to consume user-controlled input."
  }),
  regexMatcher({
    slug: "graphql-introspection-enabled",
    name: "GraphQL introspection explicitly enabled",
    category: "exposure",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bintrospection\s*:\s*true\b|GraphiQL\s*:\s*true\b|playground\s*:\s*true\b/i,
    message: "GraphQL introspection/playground appears enabled; verify production exposure."
  }),
  regexMatcher({
    slug: "xml-parser-external-entities",
    name: "XML parser may allow external entities",
    category: "xxe",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|lxml\.etree|xml2js|DOMParser)\b[\s\S]{0,600}\b(?:parse|load|fromstring)\b/i,
    negativePattern: /\b(?:disallow-doctype-decl|FEATURE_SECURE_PROCESSING|resolve_entities\s*=\s*False|noent\s*:\s*false)\b/i,
    message: "XML parsing surface has no obvious external-entity hardening nearby."
  }),
  regexMatcher({
    slug: "xpath-user-input",
    name: "XPath query receives user input",
    category: "injection",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:xpath|selectNodes|SelectSingleNode|evaluate)\s*\([^)]*(?:req\.|request\.|params|query|body|input|\$_GET|\$_POST)/i,
    message: "XPath expression appears to consume user-controlled input."
  }),
  regexMatcher({
    slug: "orm-raw-where-user-input",
    name: "ORM raw where clause receives user input",
    category: "injection",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bwhereRaw\s*\([^)]*(?:req\.|request\.|params|query|body)|\brawQuery\s*\([^)]*(?:req\.|request\.|params|query|body)/i,
    message: "Raw ORM where/query API appears to consume user-controlled input."
  }),
  regexMatcher({
    slug: "prisma-query-raw-unsafe",
    name: "Prisma raw unsafe query",
    category: "injection",
    severity: "high",
    confidence: "high",
    noiseTier: "low",
    pattern: /\$queryRawUnsafe\s*\(|\$executeRawUnsafe\s*\(/,
    message: "Prisma unsafe raw query API appears in source."
  }),
  regexMatcher({
    slug: "sequelize-literal-user-input",
    name: "Sequelize literal receives user input",
    category: "injection",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bSequelize\.literal\s*\([^)]*(?:req\.|request\.|params|query|body)/i,
    message: "Sequelize literal appears to consume user-controlled input."
  }),
  regexMatcher({
    slug: "knex-raw-user-input",
    name: "Knex raw receives user input",
    category: "injection",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bknex\.raw\s*\([^)]*(?:req\.|request\.|params|query|body)/i,
    message: "Knex raw query appears to consume user-controlled input."
  }),
  regexMatcher({
    slug: "dapper-sql-concat",
    name: "Dapper SQL concatenation",
    category: "injection",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:Query|Execute)(?:Async)?\s*<[^>]*>?\s*\([^)]*"(?:select|update|delete|insert)[^"]*"\s*\+/i,
    message: "Dapper-style SQL call appears to concatenate query text."
  }),
  regexMatcher({
    slug: "entity-framework-fromsqlraw-concat",
    name: "Entity Framework FromSqlRaw concatenation",
    category: "injection",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bFromSqlRaw\s*\([^)]*"(?:select|update|delete|insert)[^"]*"\s*\+/i,
    message: "Entity Framework FromSqlRaw appears to concatenate query text."
  }),
  regexMatcher({
    slug: "cors-reflect-origin",
    name: "CORS origin reflection",
    category: "web-security",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bAccess-Control-Allow-Origin\b[\s\S]{0,160}(?:req\.headers\.origin|request\.headers\.origin|\$http_origin|Origin)/i,
    message: "CORS Access-Control-Allow-Origin appears to reflect the request Origin."
  }),
  regexMatcher({
    slug: "helmet-disabled",
    name: "Helmet disabled",
    category: "web-security",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bhelmet\s*:\s*false\b|app\.disable\s*\(\s*["']x-powered-by["']\s*\)[\s\S]{0,400}\bhelmet\b[\s\S]{0,120}\bfalse\b/i,
    message: "HTTP security middleware appears disabled or bypassed."
  }),
  regexMatcher({
    slug: "hsts-disabled",
    name: "HSTS disabled",
    category: "web-security",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:hsts|strictTransportSecurity)\b\s*[:=]\s*false\b|Strict-Transport-Security\s*:\s*["']{2}/i,
    message: "HSTS appears disabled or empty."
  }),
  regexMatcher({
    slug: "cookie-samesite-none-no-secure",
    name: "SameSite=None without Secure",
    category: "web-security",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bsameSite\s*:\s*["']none["'][\s\S]{0,240}\bsecure\s*:\s*false\b|\bSameSite=None\b(?![\s\S]{0,80}\bSecure\b)/i,
    message: "Cookie appears configured SameSite=None without Secure."
  }),
  regexMatcher({
    slug: "file-upload-no-size-limit",
    name: "File upload without size limit",
    category: "upload",
    severity: "medium",
    confidence: "medium",
    noiseTier: "high",
    pattern: /\b(?:multer|formidable|busboy|UploadFile|MultipartFile|FileField)\b[\s\S]{0,600}\b(?:upload|file|files)\b/i,
    negativePattern: /\b(?:fileSize|maxFileSize|maxBytes|max_size|limits\s*:|MAX_CONTENT_LENGTH)\b/i,
    message: "File upload surface has no obvious size limit nearby."
  }),
  regexMatcher({
    slug: "multer-memory-unbounded",
    name: "Multer memory storage upload",
    category: "upload",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bmulter\.memoryStorage\s*\(\s*\)|storage\s*:\s*multer\.memoryStorage/i,
    negativePattern: /\blimits\s*:\s*\{[\s\S]{0,120}\bfileSize\b/i,
    message: "Multer memory storage is used without an obvious file size limit."
  }),
  regexMatcher({
    slug: "path-traversal-normalize-only",
    name: "Path traversal normalize-only guard",
    category: "path-traversal",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:normalize|resolve|clean)\s*\([^)]*(?:req\.|request\.|params|query|body)[\s\S]{0,300}\b(?:readFile|createReadStream|sendFile|download)\b/i,
    negativePattern: /\b(?:startsWith|relative|safeJoin|basename|allowlist|whitelist)\b/i,
    message: "Path normalization appears used without an obvious containment check before file access."
  }),
  regexMatcher({
    slug: "static-file-serving-dotfiles",
    name: "Static file server exposes dotfiles",
    category: "exposure",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:express\.static|serveStatic)\s*\([^)]*\{[\s\S]{0,240}\bdotfiles\s*:\s*["']allow["']/i,
    message: "Static file serving appears configured to allow dotfiles."
  }),
  regexMatcher({
    slug: "openapi-security-empty",
    name: "OpenAPI operation without security",
    category: "auth",
    severity: "medium",
    confidence: "low",
    noiseTier: "high",
    includeIf: (_text, asset) => /\.(?:ya?ml|json)$/i.test(asset.filePath),
    pattern: /\b(?:get|post|put|patch|delete):[\s\S]{0,700}\b(?:operationId|responses)\b/i,
    negativePattern: /\bsecurity\s*:\s*(?:\[[^\]]+\]|\n\s*-\s*)/i,
    message: "OpenAPI operation-like document has no obvious security requirement nearby."
  }),
  regexMatcher({
    slug: "swagger-debug-enabled",
    name: "Swagger UI exposed in production code",
    category: "exposure",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:swaggerUi|SwaggerModule|api-docs|swagger-ui)\b[\s\S]{0,400}\b(?:app|router|server)\.(?:use|get)|\bSwaggerModule\.setup\s*\(/i,
    message: "Swagger/OpenAPI UI route appears exposed; verify production access control."
  }),
  regexMatcher({
    slug: "graphql-playground-local-default",
    name: "GraphQL local playground enabled",
    category: "exposure",
    severity: "medium",
    confidence: "high",
    noiseTier: "medium",
    pattern: /\b(?:playground|graphiql)\s*:\s*true\b|ApolloServerPluginLandingPageLocalDefault\s*\(/i,
    message: "GraphQL playground or local landing page appears enabled."
  }),
  regexMatcher({
    slug: "websocket-handler-no-auth",
    name: "WebSocket handler without auth signal",
    category: "auth",
    severity: "high",
    confidence: "low",
    noiseTier: "high",
    pattern: /\b(?:new\s+WebSocketServer|io\.on\s*\(\s*["']connection|socket\.on\s*\(\s*["']connection|websocket)\b/i,
    negativePattern: /\b(?:auth|authenticate|authorize|jwt|session|token|verify)\b/i,
    message: "WebSocket connection handler has no obvious local authentication signal."
  }),
  regexMatcher({
    slug: "sse-handler-no-auth",
    name: "Server-sent events handler without auth signal",
    category: "auth",
    severity: "medium",
    confidence: "low",
    noiseTier: "high",
    pattern: /\btext\/event-stream\b|EventSource|SseEmitter|StreamingResponse\s*\(/i,
    negativePattern: /\b(?:auth|authenticate|authorize|jwt|session|token|verify)\b/i,
    message: "Server-sent event endpoint has no obvious local authentication signal."
  }),
  regexMatcher({
    slug: "grpc-handler-no-auth",
    name: "gRPC handler without auth signal",
    category: "auth",
    severity: "high",
    confidence: "low",
    noiseTier: "high",
    pattern: /\b(?:addService|grpc\.Server|@GrpcMethod|tonic::transport::Server|Register[A-Za-z]+Server)\b/i,
    negativePattern: /\b(?:auth|authenticate|authorize|jwt|session|token|verify|interceptor)\b/i,
    message: "gRPC service registration has no obvious local authentication signal."
  }),
  regexMatcher({
    slug: "rpc-method-no-auth",
    name: "RPC method without auth signal",
    category: "auth",
    severity: "high",
    confidence: "low",
    noiseTier: "high",
    pattern: /\b(?:procedure|mutation|query|rpc|JsonRpc|t\.procedure)\b[\s\S]{0,400}\b(?:handler|resolve|call)\b/i,
    negativePattern: /\b(?:auth|authenticate|authorize|jwt|session|token|verify|protectedProcedure)\b/i,
    message: "RPC-like method has no obvious local authentication signal."
  }),
  regexMatcher({
    slug: "ai-tool-shell-access",
    name: "AI tool exposes shell execution",
    category: "ai-security",
    severity: "critical",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:tool|function|command)\b[\s\S]{0,500}\b(?:shell|bash|exec|spawn|subprocess|powershell)\b/i,
    message: "AI/tool definition appears to expose shell execution capability."
  }),
  regexMatcher({
    slug: "ai-tool-file-delete",
    name: "AI tool exposes file deletion",
    category: "ai-security",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:tool|function|command)\b[\s\S]{0,500}\b(?:rm\s+-rf|unlink|deleteFile|Remove-Item|fs\.rm|rmtree)\b/i,
    message: "AI/tool definition appears to expose destructive file operations."
  }),
  regexMatcher({
    slug: "ai-tool-network-fetch",
    name: "AI tool exposes arbitrary network fetch",
    category: "ai-security",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:tool|function|command)\b[\s\S]{0,500}\b(?:fetch|axios|requests\.get|curl|httpClient)\b[\s\S]{0,240}\b(?:url|uri|endpoint)\b/i,
    message: "AI/tool definition appears to fetch arbitrary URLs."
  }),
  regexMatcher({
    slug: "ai-output-exec",
    name: "Model output flows to execution",
    category: "ai-security",
    severity: "critical",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:model|llm|completion|assistant|response)\b[\s\S]{0,240}\b(?:exec|spawn|eval|Function|subprocess|shell)\s*\(/i,
    message: "LLM/model output appears to flow into code or command execution."
  }),
  regexMatcher({
    slug: "ai-output-template-render",
    name: "Model output rendered as template",
    category: "ai-security",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:model|llm|completion|assistant|response)\b[\s\S]{0,240}\b(?:render|compile|template|innerHTML|dangerouslySetInnerHTML)\b/i,
    message: "LLM/model output appears to flow into template or HTML rendering."
  }),
  regexMatcher({
    slug: "rag-user-content-to-system",
    name: "RAG user content appended to system prompt",
    category: "ai-security",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:system|developer)\b[\s\S]{0,240}\b(?:retrieved|documents|chunks|context|userContent)\b|\b(?:retrieved|documents|chunks|context)\b[\s\S]{0,240}\brole\s*:\s*["']system["']/i,
    message: "Retrieved or user-controlled content appears to be inserted into system/developer prompt context."
  }),
  regexMatcher({
    slug: "rag-html-not-sanitized",
    name: "RAG renders retrieved HTML without sanitization",
    category: "ai-security",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:retrieved|document|chunk|rag|context)\b[\s\S]{0,300}\b(?:innerHTML|dangerouslySetInnerHTML|v-html|bypassSecurityTrustHtml)\b/i,
    negativePattern: /\b(?:sanitize|DOMPurify|escapeHtml|bleach|xss)\b/i,
    message: "Retrieved/RAG content appears to render as HTML without an obvious sanitizer."
  }),
  regexMatcher({
    slug: "mcp-tool-no-permission-check",
    name: "MCP tool without permission check",
    category: "ai-security",
    severity: "high",
    confidence: "low",
    noiseTier: "high",
    pattern: /\b(?:server\.tool|registerTool|tools\s*:\s*\[|ToolDefinition)\b[\s\S]{0,700}\b(?:handler|execute|callback)\b/i,
    negativePattern: /\b(?:permission|authorize|policy|allowlist|approval|consent|scope)\b/i,
    message: "MCP/tool registration has no obvious permission or approval check."
  }),
  regexMatcher({
    slug: "mcp-server-stdio-unrestricted",
    name: "MCP stdio server exposes local tools",
    category: "ai-security",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bStdioServerTransport\b|stdio\s*:\s*true[\s\S]{0,400}\b(?:tool|command|execute)\b/i,
    message: "MCP stdio server appears to expose local tool execution; verify trust boundary."
  }),
  regexMatcher({
    slug: "agent-memory-stores-secrets",
    name: "Agent memory stores secret-like content",
    category: "ai-security",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:memory|vector|embedding|conversation)\.(?:save|store|upsert|add)\s*\([^)]*(?:password|secret|token|apiKey|credential)/i,
    message: "Agent memory/vector store appears to persist secret-like content."
  }),
  regexMatcher({
    slug: "prompt-injection-fetch-url",
    name: "Prompt-driven URL fetch",
    category: "ai-security",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:prompt|message|instruction|completion|model)\b[\s\S]{0,300}\b(?:fetch|axios|requests\.get|curl|browser\.goto)\s*\(/i,
    message: "Prompt/model-controlled text appears near URL fetching logic."
  }),
  regexMatcher({
    slug: "browser-automation-unsafe-url",
    name: "Browser automation navigates to untrusted URL",
    category: "ai-security",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:page|browser|context)\.(?:goto|open|navigate)\s*\([^)]*(?:req\.|request\.|params|query|body|message|prompt|url)/i,
    message: "Browser automation appears to navigate to untrusted input."
  }),
  regexMatcher({
    slug: "function-calling-arguments-unvalidated",
    name: "Function-calling arguments used without validation",
    category: "ai-security",
    severity: "medium",
    confidence: "low",
    noiseTier: "high",
    pattern: /\b(?:toolCall|function_call|arguments|args)\b[\s\S]{0,300}\b(?:JSON\.parse|parse)\s*\(/i,
    negativePattern: /\b(?:zod|schema|validate|safeParse|ajv|joi|yup)\b/i,
    message: "Tool/function-call arguments appear parsed without obvious schema validation."
  }),
  regexMatcher({
    slug: "github-actions-permissions-write-all",
    name: "GitHub Actions write-all permissions",
    category: "ci-cd",
    severity: "high",
    confidence: "high",
    noiseTier: "low",
    includeIf: (_text, asset) => asset.filePath.includes(".github/workflows/"),
    pattern: /\bpermissions\s*:\s*write-all\b/i,
    message: "Workflow grants write-all token permissions."
  }),
  regexMatcher({
    slug: "github-actions-self-hosted-pr",
    name: "Self-hosted GitHub runner on PR workflow",
    category: "ci-cd",
    severity: "critical",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.filePath.includes(".github/workflows/"),
    pattern: /\bon\s*:\s*(?:\[?[^\n]*pull_request|[\s\S]{0,500}pull_request:)[\s\S]{0,1200}\bruns-on\s*:\s*(?:\[?[^\n]*self-hosted|self-hosted)/i,
    message: "Pull request workflow appears to run on a self-hosted runner."
  }),
  regexMatcher({
    slug: "github-actions-workflow-dispatch-shell",
    name: "Workflow dispatch input used in shell",
    category: "ci-cd",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.filePath.includes(".github/workflows/"),
    pattern: /\bworkflow_dispatch\b[\s\S]{0,1600}\brun\s*:\s*[^\n]*\$\{\{\s*(?:github\.event\.inputs|inputs)\./i,
    message: "workflow_dispatch input appears interpolated into a shell command."
  }),
  regexMatcher({
    slug: "github-actions-env-secret-echo",
    name: "GitHub Actions secret echo",
    category: "ci-cd",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.filePath.includes(".github/workflows/"),
    pattern: /\brun\s*:\s*(?:echo|printf|cat)[^\n]*\$\{\{\s*secrets\./i,
    message: "Workflow appears to print a secret in a shell step."
  }),
  regexMatcher({
    slug: "gitlab-ci-privileged-docker",
    name: "GitLab CI privileged Docker service",
    category: "ci-cd",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.filePath.endsWith(".gitlab-ci.yml") || asset.filePath.endsWith(".gitlab-ci.yaml"),
    pattern: /\bprivileged\s*:\s*true\b|docker:dind/i,
    message: "GitLab CI enables privileged mode or Docker-in-Docker."
  }),
  regexMatcher({
    slug: "gitlab-ci-curl-shell",
    name: "GitLab CI curl pipe shell",
    category: "ci-cd",
    severity: "high",
    confidence: "medium",
    noiseTier: "low",
    includeIf: (_text, asset) => asset.filePath.endsWith(".gitlab-ci.yml") || asset.filePath.endsWith(".gitlab-ci.yaml"),
    pattern: /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sh|bash)\b/i,
    message: "GitLab CI downloads and executes a remote script."
  }),
  regexMatcher({
    slug: "circleci-unpinned-orb",
    name: "CircleCI orb version is broad",
    category: "ci-cd",
    severity: "medium",
    confidence: "medium",
    noiseTier: "high",
    includeIf: (_text, asset) => asset.filePath.includes(".circleci/"),
    pattern: /\borbs\s*:[\s\S]{0,400}\/(?:volatile|dev|latest|@?[\d.]+)\b/i,
    message: "CircleCI orb reference appears mutable or broadly pinned."
  }),
  regexMatcher({
    slug: "jenkins-shell-user-param",
    name: "Jenkins shell uses build parameter",
    category: "ci-cd",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => /Jenkinsfile$/i.test(asset.filePath),
    pattern: /\bsh\s+["'][^"']*\$\{?params\./i,
    message: "Jenkins shell step appears to interpolate user-controlled build parameters."
  }),
  regexMatcher({
    slug: "npm-preinstall-network",
    name: "NPM lifecycle script downloads code",
    category: "supply-chain",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.filePath.endsWith("package.json"),
    pattern: /"(?:preinstall|install|postinstall|prepare)"\s*:\s*"[^"]*(?:curl|wget|Invoke-WebRequest|powershell|bash -c)/i,
    message: "Package lifecycle script appears to download or execute remote code."
  }),
  regexMatcher({
    slug: "pip-extra-index-url-http",
    name: "pip extra index over HTTP",
    category: "supply-chain",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /(?:--extra-index-url|extra-index-url)\s*=?\s*http:\/\//i,
    message: "pip extra index URL uses plaintext HTTP."
  }),
  regexMatcher({
    slug: "gradle-dynamic-version",
    name: "Gradle dynamic dependency version",
    category: "supply-chain",
    severity: "medium",
    confidence: "medium",
    noiseTier: "high",
    includeIf: (_text, asset) => /\.(?:gradle|gradle\.kts)$/i.test(asset.filePath),
    pattern: /["'][A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+:(?:latest\.release|latest\.integration|\+|\d+\.\+)["']/i,
    message: "Gradle dependency uses a dynamic version."
  }),
  regexMatcher({
    slug: "maven-http-repository",
    name: "Maven repository over HTTP",
    category: "supply-chain",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /<repository>[\s\S]{0,600}<url>\s*http:\/\/|maven\s*\{[\s\S]{0,200}url\s*=\s*uri\(["']http:\/\//i,
    message: "Maven repository uses plaintext HTTP."
  }),
  regexMatcher({
    slug: "go-get-insecure",
    name: "Go module allows insecure source",
    category: "supply-chain",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bGOINSECURE\b|replace\s+[\w./-]+\s+=>\s+http:\/\//i,
    message: "Go module configuration allows insecure module transport or replacement."
  }),
  regexMatcher({
    slug: "cargo-git-unpinned",
    name: "Cargo git dependency unpinned",
    category: "supply-chain",
    severity: "medium",
    confidence: "medium",
    noiseTier: "high",
    includeIf: (_text, asset) => asset.filePath.endsWith("Cargo.toml"),
    pattern: /\bgit\s*=\s*["']https?:\/\/[^"']+["']/i,
    negativePattern: /\b(?:rev|tag)\s*=\s*["'][^"']+["']/i,
    message: "Cargo git dependency has no obvious immutable rev or tag."
  }),
  regexMatcher({
    slug: "terraform-sg-all-egress",
    name: "Terraform unrestricted egress",
    category: "iac",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.filePath.endsWith(".tf"),
    pattern: /\begress\s*\{[\s\S]{0,600}cidr_blocks\s*=\s*\[[^\]]*["']0\.0\.0\.0\/0["'][\s\S]{0,200}from_port\s*=\s*0[\s\S]{0,200}to_port\s*=\s*0/i,
    message: "Terraform security group appears to allow unrestricted egress."
  }),
  regexMatcher({
    slug: "terraform-rds-public",
    name: "Terraform public RDS instance",
    category: "iac",
    severity: "high",
    confidence: "high",
    noiseTier: "low",
    includeIf: (_text, asset) => asset.filePath.endsWith(".tf"),
    pattern: /resource\s+"aws_db_instance"[\s\S]{0,1200}publicly_accessible\s*=\s*true/i,
    message: "Terraform RDS instance is publicly accessible."
  }),
  regexMatcher({
    slug: "terraform-rds-no-encryption",
    name: "Terraform RDS storage encryption disabled",
    category: "iac",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.filePath.endsWith(".tf"),
    pattern: /resource\s+"aws_db_instance"[\s\S]{0,1200}storage_encrypted\s*=\s*false/i,
    message: "Terraform RDS storage encryption appears disabled."
  }),
  regexMatcher({
    slug: "terraform-s3-force-destroy",
    name: "Terraform S3 force destroy",
    category: "iac",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.filePath.endsWith(".tf"),
    pattern: /resource\s+"aws_s3_bucket"[\s\S]{0,800}force_destroy\s*=\s*true/i,
    message: "Terraform S3 bucket has force_destroy enabled."
  }),
  regexMatcher({
    slug: "terraform-cloudtrail-disabled",
    name: "Terraform CloudTrail disabled",
    category: "iac",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.filePath.endsWith(".tf"),
    pattern: /resource\s+"aws_cloudtrail"[\s\S]{0,1000}enable_logging\s*=\s*false/i,
    message: "Terraform CloudTrail logging appears disabled."
  }),
  regexMatcher({
    slug: "terraform-imds-v1",
    name: "Terraform EC2 allows IMDSv1",
    category: "iac",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.filePath.endsWith(".tf"),
    pattern: /metadata_options\s*\{[\s\S]{0,400}http_tokens\s*=\s*["']optional["']/i,
    message: "Terraform EC2 metadata options allow IMDSv1."
  }),
  regexMatcher({
    slug: "terraform-lambda-env-secret",
    name: "Terraform Lambda secret env var",
    category: "secrets",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.filePath.endsWith(".tf"),
    pattern: /resource\s+"aws_lambda_function"[\s\S]{0,1600}environment\s*\{[\s\S]{0,800}(?:PASSWORD|SECRET|TOKEN|API_KEY)\s*=\s*"[^"]+"/i,
    message: "Terraform Lambda environment appears to hardcode a secret-like value."
  }),
  regexMatcher({
    slug: "terraform-ecs-privileged",
    name: "Terraform ECS privileged container",
    category: "iac",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.filePath.endsWith(".tf"),
    pattern: /\bcontainer_definitions\b[\s\S]{0,2000}"privileged"\s*:\s*true/i,
    message: "Terraform ECS container definition enables privileged mode."
  }),
  regexMatcher({
    slug: "k8s-automount-service-account",
    name: "Kubernetes service account token automount",
    category: "iac",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.language === "yaml",
    pattern: /automountServiceAccountToken\s*:\s*true/i,
    message: "Kubernetes workload explicitly automounts a service account token."
  }),
  regexMatcher({
    slug: "k8s-host-network",
    name: "Kubernetes host networking",
    category: "iac",
    severity: "high",
    confidence: "high",
    noiseTier: "low",
    includeIf: (_text, asset) => asset.language === "yaml",
    pattern: /\bhostNetwork\s*:\s*true\b/i,
    message: "Kubernetes workload enables host networking."
  }),
  regexMatcher({
    slug: "k8s-capability-add",
    name: "Kubernetes adds Linux capabilities",
    category: "iac",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.language === "yaml",
    pattern: /capabilities\s*:\s*\n[\s\S]{0,200}add\s*:\s*\n\s*-\s*(?:SYS_ADMIN|NET_ADMIN|DAC_OVERRIDE|ALL)/i,
    message: "Kubernetes container adds powerful Linux capabilities."
  }),
  regexMatcher({
    slug: "k8s-allow-privilege-escalation",
    name: "Kubernetes allows privilege escalation",
    category: "iac",
    severity: "high",
    confidence: "high",
    noiseTier: "low",
    includeIf: (_text, asset) => asset.language === "yaml",
    pattern: /\ballowPrivilegeEscalation\s*:\s*true\b/i,
    message: "Kubernetes container allows privilege escalation."
  }),
  regexMatcher({
    slug: "k8s-image-latest",
    name: "Kubernetes mutable image tag",
    category: "iac",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.language === "yaml",
    pattern: /\bimage\s*:\s*[^@\s]+:(?:latest|main|master)\b|\bimage\s*:\s*[^@\s:]+\/?[^@\s:]+$/im,
    message: "Kubernetes image appears to use a mutable tag or no digest."
  }),
  regexMatcher({
    slug: "k8s-no-readonly-rootfs",
    name: "Kubernetes root filesystem writable",
    category: "iac",
    severity: "medium",
    confidence: "low",
    noiseTier: "high",
    includeIf: (_text, asset) => asset.language === "yaml",
    pattern: /\bcontainers\s*:\s*\n[\s\S]{0,1000}\bsecurityContext\s*:/i,
    negativePattern: /\breadOnlyRootFilesystem\s*:\s*true\b/i,
    message: "Kubernetes container security context lacks readOnlyRootFilesystem true nearby."
  }),
  regexMatcher({
    slug: "k8s-service-loadbalancer-public",
    name: "Kubernetes public LoadBalancer service",
    category: "iac",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.language === "yaml",
    pattern: /\bkind\s*:\s*Service\b[\s\S]{0,800}\btype\s*:\s*LoadBalancer\b/i,
    negativePattern: /\b(?:loadBalancerSourceRanges|internal-load-balancer|aws-load-balancer-internal|azure-load-balancer-internal)\b/i,
    message: "Kubernetes LoadBalancer service has no obvious source range or internal-only annotation."
  }),
  regexMatcher({
    slug: "helm-secret-template",
    name: "Helm template emits secret from values",
    category: "secrets",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.filePath.includes("templates/") && /\.(?:ya?ml|tpl)$/i.test(asset.filePath),
    pattern: /\bkind\s*:\s*Secret\b[\s\S]{0,800}\{\{\s*\.Values\.[^}]+(?:password|secret|token|key)[^}]*\}\}/i,
    message: "Helm Secret template appears to source secret-like values directly from chart values."
  }),
  regexMatcher({
    slug: "dockerfile-secret-arg",
    name: "Dockerfile secret ARG",
    category: "container",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.language === "dockerfile",
    pattern: /^\s*(?:ARG|ENV)\s+[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)[A-Z0-9_]*\s*=/im,
    message: "Dockerfile ARG/ENV appears to define secret-like data."
  }),
  regexMatcher({
    slug: "dockerfile-ssh-key-copy",
    name: "Dockerfile copies SSH key",
    category: "container",
    severity: "critical",
    confidence: "high",
    noiseTier: "low",
    includeIf: (_text, asset) => asset.language === "dockerfile",
    pattern: /^\s*(?:COPY|ADD)\s+.*(?:id_rsa|\.ssh|private_key|\.pem)\b/im,
    message: "Dockerfile appears to copy private key or SSH material into an image."
  }),
  regexMatcher({
    slug: "docker-compose-privileged",
    name: "Docker Compose privileged container",
    category: "container",
    severity: "high",
    confidence: "high",
    noiseTier: "low",
    includeIf: (_text, asset) => /docker-compose|compose\.ya?ml$/i.test(asset.filePath),
    pattern: /\bprivileged\s*:\s*true\b/i,
    message: "Docker Compose service enables privileged mode."
  }),
  regexMatcher({
    slug: "docker-compose-host-network",
    name: "Docker Compose host network",
    category: "container",
    severity: "high",
    confidence: "high",
    noiseTier: "low",
    includeIf: (_text, asset) => /docker-compose|compose\.ya?ml$/i.test(asset.filePath),
    pattern: /\bnetwork_mode\s*:\s*["']?host["']?/i,
    message: "Docker Compose service uses host networking."
  }),
  regexMatcher({
    slug: "android-allow-backup-true",
    name: "Android backup allowed",
    category: "mobile",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.filePath.endsWith("AndroidManifest.xml"),
    pattern: /android:allowBackup\s*=\s*["']true["']/i,
    message: "Android manifest allows application data backup."
  }),
  regexMatcher({
    slug: "android-cleartext-traffic",
    name: "Android cleartext traffic allowed",
    category: "mobile",
    severity: "high",
    confidence: "high",
    noiseTier: "low",
    includeIf: (_text, asset) => asset.filePath.endsWith("AndroidManifest.xml") || asset.filePath.endsWith("network_security_config.xml"),
    pattern: /usesCleartextTraffic\s*=\s*["']true["']|cleartextTrafficPermitted\s*=\s*["']true["']/i,
    message: "Android configuration permits cleartext network traffic."
  }),
  regexMatcher({
    slug: "ios-app-transport-security-disabled",
    name: "iOS App Transport Security disabled",
    category: "mobile",
    severity: "high",
    confidence: "high",
    noiseTier: "low",
    includeIf: (_text, asset) => asset.filePath.endsWith("Info.plist"),
    pattern: /NSAppTransportSecurity[\s\S]{0,800}NSAllowsArbitraryLoads[\s\S]{0,120}<true\/>/i,
    message: "iOS App Transport Security arbitrary loads are enabled."
  }),
  regexMatcher({
    slug: "ios-webview-javascript-enabled",
    name: "iOS WebView JavaScript enabled",
    category: "mobile",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bjavaScriptEnabled\s*=\s*true\b|preferences\.javaScriptEnabled\s*=\s*true\b/,
    message: "iOS WebView JavaScript appears enabled; verify untrusted content cannot load."
  }),
  regexMatcher({
    slug: "electron-node-integration",
    name: "Electron nodeIntegration enabled",
    category: "desktop",
    severity: "critical",
    confidence: "high",
    noiseTier: "low",
    pattern: /\bnodeIntegration\s*:\s*true\b/i,
    message: "Electron nodeIntegration is enabled."
  }),
  regexMatcher({
    slug: "electron-context-isolation-disabled",
    name: "Electron contextIsolation disabled",
    category: "desktop",
    severity: "high",
    confidence: "high",
    noiseTier: "low",
    pattern: /\bcontextIsolation\s*:\s*false\b/i,
    message: "Electron contextIsolation is disabled."
  }),
  regexMatcher({
    slug: "react-native-insecure-storage",
    name: "React Native sensitive AsyncStorage",
    category: "mobile",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bAsyncStorage\.(?:setItem|getItem)\s*\([^)]*(?:token|secret|password|credential|apiKey)/i,
    message: "React Native AsyncStorage appears to store or read sensitive data."
  }),
  regexMatcher({
    slug: "surface-apex-rest-resource",
    name: "Apex REST resource surface",
    category: "entrypoint",
    severity: "info",
    confidence: "medium",
    noiseTier: "high",
    filePatterns: ["**/*.{cls,apex}"],
    examples: ["@RestResource(urlMapping='/v1/users/*') global class Api { @HttpGet global static void get() {} }"],
    provenance: "proofstrike",
    pattern: /@RestResource|@Http(?:Get|Post|Put|Patch|Delete)/i,
    message: "Apex REST resource or HTTP method annotation creates a reviewable entry point."
  })
];

export const SECURITY_SURFACE_SEEDS: readonly string[] = `
surface-agent-prompt-boundary
surface-agent-loop-budget
surface-agent-tool-schema
surface-agent-tool-permission
surface-agent-memory-sensitivity
surface-agent-browser-navigation
surface-agent-shell-capability
surface-agent-file-mutation
surface-agent-network-fetch
surface-agent-output-execution
surface-agent-output-rendering
surface-agent-rag-system-context
surface-agent-rag-html-rendering
surface-agent-mcp-stdio-tooling
surface-agent-function-call-validation
surface-auth-jwt-claims
surface-auth-jwt-algorithm
surface-auth-session-cookie
surface-auth-oauth-callback
surface-auth-saml-signature
surface-auth-ldap-bind
surface-auth-api-key-location
surface-auth-admin-trust-boundary
surface-auth-development-bypass
surface-auth-rate-limit
surface-auth-webhook-signature
surface-auth-slack-signing
surface-tenant-request-scope
surface-cache-request-key
surface-cache-tenant-scope
surface-cache-poisoning-vector
surface-web-cors-origin
surface-web-cors-credentials
surface-web-redirect-target
surface-web-postmessage-origin
surface-web-hsts-config
surface-web-security-headers
surface-web-stacktrace-response
surface-web-debug-route
surface-web-openapi-security
surface-web-swagger-exposure
surface-web-graphql-playground
surface-web-graphql-resolver
surface-web-graphql-introspection
surface-websocket-auth-boundary
surface-sse-auth-boundary
surface-grpc-auth-boundary
surface-rpc-auth-boundary
surface-express-http-entrypoint
surface-fastify-http-entrypoint
surface-hono-http-entrypoint
surface-koa-http-entrypoint
surface-hapi-http-entrypoint
surface-nestjs-controller-entrypoint
surface-nextjs-route-handler
surface-nextjs-server-action
surface-nextjs-middleware
surface-nextjs-image-proxy
surface-nextjs-internal-header
surface-remix-loader-action
surface-sveltekit-endpoint
surface-nuxt-event-handler
surface-astro-endpoint
surface-workers-fetch-handler
surface-deno-http-server
surface-bun-http-server
surface-socketio-connection
surface-bullmq-processor
surface-trpc-public-procedure
surface-python-fastapi-route
surface-python-flask-route
surface-python-django-view
surface-python-aiohttp-route
surface-python-sanic-route
surface-python-starlette-route
surface-python-tornado-handler
surface-python-falcon-resource
surface-python-bottle-route
surface-python-celery-task
surface-python-airflow-dag
surface-ruby-rails-controller
surface-ruby-sinatra-route
surface-ruby-grape-endpoint
surface-ruby-roda-route
surface-ruby-hanami-action
surface-php-laravel-route
surface-php-symfony-controller
surface-php-slim-route
surface-php-wordpress-rest
surface-php-drupal-controller
surface-php-yii-controller
surface-php-cake-controller
surface-php-codeigniter-controller
surface-php-magento-controller
surface-go-http-handler
surface-go-gin-route
surface-go-fiber-route
surface-go-echo-route
surface-go-chi-route
surface-go-gorilla-route
surface-go-buffalo-route
surface-go-cobra-command
surface-rust-axum-route
surface-rust-actix-route
surface-rust-rocket-route
surface-rust-poem-route
surface-rust-warp-filter
surface-rust-tide-route
surface-rust-tonic-service
surface-rust-lambda-runtime
surface-jvm-spring-controller
surface-jvm-ktor-route
surface-jvm-micronaut-controller
surface-jvm-jaxrs-resource
surface-dotnet-controller
surface-dotnet-minimal-api
surface-dotnet-razor-page
surface-dotnet-azure-function
surface-azure-http-function
surface-gcp-http-function
surface-aws-lambda-handler
surface-apex-rest-resource
surface-swift-vapor-route
surface-dart-shelf-handler
surface-elixir-phoenix-controller
surface-erlang-cowboy-handler
surface-clojure-ring-handler
surface-crystal-kemal-route
surface-lua-nginx-handler
surface-protobuf-rpc-service
surface-connect-rpc-handler
surface-sql-js-raw
surface-sql-python-raw
surface-sql-go-raw
surface-sql-ruby-raw
surface-sql-php-raw
surface-sql-jvm-raw
surface-sql-dotnet-raw
surface-sql-warehouse-raw
surface-soql-raw
surface-nosql-javascript
surface-nosql-python
surface-orm-prisma-raw
surface-orm-drizzle-raw
surface-orm-drizzle-mass-assignment
surface-orm-sequelize-literal
surface-orm-knex-raw
surface-orm-dapper-raw
surface-orm-ef-raw
surface-injection-template
surface-injection-ldap
surface-injection-xpath
surface-injection-order-by
surface-injection-spread-object
surface-injection-zod-passthrough
surface-injection-xml-parser
surface-deserialization-python-pickle
surface-deserialization-python-yaml
surface-deserialization-java-object
surface-deserialization-dotnet-binary
surface-deserialization-php-unserialize
surface-deserialization-ruby-marshal
surface-rce-node-child-process
surface-rce-node-vm
surface-rce-java-runtime
surface-rce-python-subprocess
surface-rce-ruby-command
surface-rce-go-command
surface-rce-rust-command
surface-filesystem-path-read
surface-filesystem-path-write
surface-filesystem-zip-extract
surface-filesystem-symlink-boundary
surface-filesystem-nonatomic-update
surface-upload-size-limit
surface-upload-memory-buffer
surface-upload-type-filter
surface-ssrf-generic-fetch
surface-ssrf-cloud-metadata
surface-ssrf-url-regex
surface-ssrf-redirect-follow
surface-secrets-private-key
surface-secrets-cloud-key
surface-secrets-database-url
surface-secrets-jwt-secret
surface-secrets-npm-token
surface-secrets-git-token
surface-secrets-payment-key
surface-secrets-messaging-key
surface-secrets-webhook-url
surface-secrets-basic-auth-url
surface-secrets-kubeconfig
surface-secrets-docker-auth
surface-secrets-terraform-default
surface-secrets-env-fallback
surface-secrets-log-sink
surface-crypto-weak-hash
surface-crypto-low-bcrypt
surface-crypto-low-pbkdf2
surface-crypto-static-iv
surface-crypto-tls-disabled
surface-crypto-lua-weakness
surface-ci-github-token-permission
surface-ci-github-pr-privilege
surface-ci-github-self-hosted
surface-ci-workflow-input-shell
surface-ci-secret-echo
surface-ci-curl-shell
surface-ci-gitlab-privileged
surface-ci-circle-orb
surface-ci-jenkins-parameter-shell
surface-supplychain-npm-lifecycle
surface-supplychain-package-registry
surface-supplychain-unpinned-git
surface-supplychain-pip-index
surface-supplychain-gradle-dynamic
surface-supplychain-maven-http
surface-supplychain-go-insecure
surface-supplychain-cargo-git
surface-container-docker-root
surface-container-docker-latest
surface-container-docker-remote-add
surface-container-docker-secret
surface-container-docker-ssh-copy
surface-container-compose-privileged
surface-container-compose-host-network
surface-kubernetes-privileged
surface-kubernetes-hostpath
surface-kubernetes-root-user
surface-kubernetes-secret-env
surface-kubernetes-token-automount
surface-kubernetes-host-network
surface-kubernetes-capability-add
surface-kubernetes-privilege-escalation
surface-kubernetes-image-tag
surface-kubernetes-loadbalancer
surface-kubernetes-readonly-rootfs
surface-terraform-public-ingress
surface-terraform-iam-wildcard
surface-terraform-unencrypted-storage
surface-terraform-public-bucket
surface-terraform-secret-data
surface-terraform-unpinned-module
surface-terraform-rds-public
surface-terraform-rds-encryption
surface-terraform-cloudtrail-logging
surface-terraform-imds-token
surface-terraform-lambda-secret
surface-terraform-ecs-privileged
surface-mobile-android-exported
surface-mobile-android-backup
surface-mobile-android-cleartext
surface-mobile-ios-url-scheme
surface-mobile-ios-ats
surface-mobile-ios-webview-js
surface-mobile-reactnative-storage
surface-desktop-electron-node
surface-desktop-electron-isolation
`.trim().split(/\s+/);

const SECURITY_SURFACE_MATCHERS: MatcherPlugin[] = SECURITY_SURFACE_SEEDS.map(securitySurfaceMatcher);
const FRAMEWORK_SPECIALIST_MATCHERS: MatcherPlugin[] = createFrameworkSpecialistMatchers();

export const BUILTIN_MATCHERS: MatcherPlugin[] = uniqueMatchers([
  ...SECURITY_SURFACE_MATCHERS,
  ...FRAMEWORK_SPECIALIST_MATCHERS,
  regexMatcher({
    slug: "secrets-exposure",
    name: "Secret-like value in source",
    category: "secrets",
    severity: "critical",
    confidence: "high",
    noiseTier: "low",
    pattern: /\b(?:api[_-]?key|secret|token|password|private[_-]?key)\b\s*[:=]\s*["'][A-Za-z0-9_\-./+=]{16,}["']/i,
    message: "Potential hardcoded secret or credential."
  }),
  regexMatcher({
    slug: "env-exposure",
    name: "Secret-like public environment variable",
    category: "secrets",
    severity: "high",
    confidence: "medium",
    noiseTier: "low",
    pattern: /\b(?:NEXT_PUBLIC|PUBLIC|VITE|REACT_APP)_[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PRIVATE|KEY)[A-Z0-9_]*\b/,
    message: "Public client-exposed environment variable name appears to contain a secret-bearing term."
  }),
  regexMatcher({
    slug: "secret-in-log",
    name: "Secret-like value logged",
    category: "secrets",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:console\.log|logger\.(?:info|debug|warn|error)|print|puts)\s*\([^)]*(?:password|secret|token|authorization|cookie)/i,
    message: "Secret-like value appears to be written to logs."
  }),
  regexMatcher({
    slug: "sql-injection",
    name: "Raw SQL with interpolation",
    category: "injection",
    severity: "high",
    confidence: "medium",
    noiseTier: "low",
    pattern: /(?:query|execute|raw|sql)\s*\([^)]*(?:\+|\$\{|format\()/is,
    message: "Raw SQL appears to include interpolation or string concatenation."
  }),
  regexMatcher({
    slug: "prisma-raw-sql",
    name: "Prisma raw SQL with interpolation",
    category: "injection",
    severity: "high",
    confidence: "medium",
    noiseTier: "low",
    pattern: /\b(?:\$queryRawUnsafe|\$executeRawUnsafe)\s*\(|\b(?:\$queryRaw|\$executeRaw)\s*`[\s\S]*\$\{/,
    message: "Prisma raw SQL appears to use unsafe raw execution or interpolated template SQL."
  }),
  regexMatcher({
    slug: "drizzle-raw-sql",
    name: "Drizzle raw SQL with interpolation",
    category: "injection",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bsql\s*`[\s\S]*\$\{|\.execute\s*\(\s*sql\s*`[\s\S]*\$\{/,
    message: "Drizzle/raw SQL template appears to include interpolation that needs parameterization review."
  }),
  regexMatcher({
    slug: "nosql-injection",
    name: "NoSQL query with request body",
    category: "injection",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\.(?:find|findOne|update|deleteOne|deleteMany)\s*\([^)]*(?:req\.body|request\.json|body)/is,
    message: "NoSQL query appears to use request-controlled object data."
  }),
  regexMatcher({
    slug: "mass-assignment",
    name: "Mass assignment from request body",
    category: "authorization",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:create|update|insert|save)\s*\([^)]*(?:data\s*:\s*)?(?:req\.body|request\.body|body)\b/is,
    negativePattern: /\b(?:pick|omit|allowlist|whitelist|schema\.parse|safeParse|z\.object|joi\.object|yup\.object)\b/i,
    message: "Request body appears to be passed into persistence without an obvious allowlist or schema boundary."
  }),
  regexMatcher({
    slug: "tenant-id-from-request",
    name: "Tenant identifier from request near data access",
    category: "authorization",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:tenantId|workspaceId|orgId|teamId|accountId)\b[\s\S]{0,500}\b(?:req\.(?:body|query|params)|request\.(?:body|query|params)|body|query|params)\b[\s\S]{0,800}\b(?:db|prisma|drizzle|query|find|findMany|update|delete|insert)\b/i,
    message: "Request-controlled tenant or workspace identifier appears near data access."
  }),
  regexMatcher({
    slug: "command-injection",
    name: "Command execution",
    category: "rce",
    severity: "critical",
    confidence: "medium",
    noiseTier: "low",
    pattern: /\b(?:exec|execSync|spawn|spawnSync|system|popen|subprocess\.(?:run|Popen|call))\s*\(/,
    message: "Command execution sink needs attacker-input review."
  }),
  regexMatcher({
    slug: "unsafe-deserialization",
    name: "Unsafe deserialization",
    category: "injection",
    severity: "critical",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:pickle\.loads|yaml\.load|unserialize|ObjectInputStream|BinaryFormatter|Marshal\.load)\s*\(/,
    message: "Unsafe deserialization API requires review of attacker-controllable input."
  }),
  regexMatcher({
    slug: "prototype-pollution",
    name: "Object merge from request body",
    category: "injection",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:Object\.assign|merge|defaultsDeep|lodash\.merge|_.merge)\s*\([^)]*(?:req\.body|request\.body|body)\b/is,
    message: "Request body appears to be merged into an object, which can create prototype pollution or mass-assignment risk."
  }),
  regexMatcher({
    slug: "ssrf",
    name: "Server-side request with variable URL",
    category: "ssrf",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:fetch|axios\.(?:get|post|request)|requests\.(?:get|post|request)|http\.get|https\.get)\s*\([^"']/,
    message: "Outbound request appears to use a variable URL."
  }),
  regexMatcher({
    slug: "untrusted-redirect-following",
    name: "Server request follows untrusted redirects",
    category: "ssrf",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:fetch|axios|requests)\b[\s\S]{0,300}\b(?:maxRedirects\s*:\s*[1-9]|allow_redirects\s*=\s*True|redirect\s*:\s*["']follow["'])/i,
    message: "Outbound request configuration follows redirects; verify SSRF allowlists cover redirected targets."
  }),
  regexMatcher({
    slug: "path-traversal",
    name: "Path construction from request input",
    category: "path-traversal",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:readFile|writeFile|createReadStream|sendFile|open)\s*\([^)]*(?:req\.|request\.|params|query|body)/is,
    message: "File operation appears near request-controlled input."
  }),
  regexMatcher({
    slug: "file-upload-unrestricted",
    name: "File upload without obvious limits",
    category: "upload",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:multer|formidable|busboy|upload\.single|upload\.array|FileInterceptor)\b/i,
    negativePattern: /\b(?:fileFilter|limits|mimetype|contentType|maxFileSize|sizeLimit|allowedTypes)\b/i,
    message: "File upload handler has no obvious local size/type restriction."
  }),
  regexMatcher({
    slug: "dangerous-html",
    name: "Dangerous HTML rendering",
    category: "xss",
    severity: "high",
    confidence: "medium",
    noiseTier: "low",
    pattern: /dangerouslySetInnerHTML|innerHTML\s*=|v-html=|unsafeHTML/,
    message: "Dangerous HTML rendering requires escaping/source review."
  }),
  regexMatcher({
    slug: "postmessage-origin",
    name: "postMessage without strict target origin",
    category: "xss",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\.postMessage\s*\([^,]+,\s*["']\*["']\s*\)/,
    message: "postMessage uses wildcard target origin."
  }),
  regexMatcher({
    slug: "regex-dos",
    name: "Dynamic regular expression from request input",
    category: "availability",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bnew\s+RegExp\s*\([^)]*(?:req\.|request\.|query|params|body)/is,
    message: "Dynamic regular expression appears to use request-controlled input."
  }),
  regexMatcher({
    slug: "open-redirect",
    name: "User-controlled redirect",
    category: "open-redirect",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:redirect|res\.redirect|Response\.redirect)\s*\([^)]*(?:req\.|request\.|query|params|body|url)/is,
    message: "Redirect appears to use request-controlled data."
  }),
  regexMatcher({
    slug: "cors-wildcard",
    name: "Wildcard CORS origin",
    category: "auth",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*["']|cors\s*\(\s*\{[\s\S]{0,300}origin\s*:\s*["']\*["']/i,
    message: "CORS configuration allows wildcard origins."
  }),
  regexMatcher({
    slug: "cors-credentials-wildcard",
    name: "Credentialed CORS with broad origin",
    category: "auth",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /cors\s*\(\s*\{[\s\S]{0,300}credentials\s*:\s*true[\s\S]{0,300}origin\s*:\s*["']\*["']/i,
    message: "Credentialed CORS appears to allow a wildcard origin."
  }),
  regexMatcher({
    slug: "session-cookie-insecure",
    name: "Session cookie missing security attributes",
    category: "auth",
    severity: "high",
    confidence: "medium",
    noiseTier: "low",
    pattern: /\b(?:res\.cookie|cookies\.set|setCookie)\s*\([^)]*(?:session|sid|jwt|token)/is,
    negativePattern: /\bhttpOnly\b[\s\S]{0,120}\bsecure\b|\bsecure\b[\s\S]{0,120}\bhttpOnly\b/i,
    message: "Session-like cookie is set without obvious httpOnly and secure attributes nearby."
  }),
  regexMatcher({
    slug: "jwt-decode-without-verify",
    name: "JWT decoded without verification",
    category: "auth",
    severity: "high",
    confidence: "high",
    noiseTier: "low",
    pattern: /\bjwt\.decode\s*\(/,
    message: "JWT decode does not verify signature or claims; use verification at trust boundaries."
  }),
  regexMatcher({
    slug: "jwt-algorithm-confusion",
    name: "JWT algorithm confusion risk",
    category: "auth",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bjwt\.verify\s*\([^)]*algorithms\s*:\s*\[[^\]]*["']none["']|alg\s*:\s*["']none["']/is,
    message: "JWT verification appears to allow or handle the none algorithm."
  }),
  regexMatcher({
    slug: "public-admin-route",
    name: "Admin route without local auth signal",
    category: "auth",
    severity: "critical",
    confidence: "medium",
    noiseTier: "low",
    pattern: /\b(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*["'`][^"'`]*admin/i,
    negativePattern: /\b(?:requireAuth|requireUser|requireAdmin|authorize|isAuthenticated|permission|role|session|jwt|verifyToken)\b/i,
    message: "Admin route has no obvious local authentication or authorization signal."
  }),
  regexMatcher({
    slug: "webhook-no-signature",
    name: "Webhook handler without obvious signature verification",
    category: "auth",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (text, asset) => /webhook/i.test(asset.filePath) || /webhook/i.test(text),
    pattern: /(?:router|app)\.(?:post|put)|POST\s*\(/,
    negativePattern: /signature|hmac|verify|svix|stripe\.webhooks\.constructEvent/i,
    message: "Webhook-like handler has no obvious signature verification in this file."
  }),
  regexMatcher({
    slug: "debug-endpoint",
    name: "Debug endpoint exposed",
    category: "exposure",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*["'`][^"'`]*(?:debug|dump|internal|metrics|actuator|admin\/debug)/i,
    negativePattern: /\b(?:requireAdmin|authorize|internalOnly|isInternal|NODE_ENV\s*[!=]==?\s*["']production["'])\b/i,
    message: "Debug or internal endpoint lacks an obvious local access restriction."
  }),
  regexMatcher({
    slug: "graphql-playground-enabled",
    name: "GraphQL playground or introspection enabled",
    category: "exposure",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:introspection|graphiql|playground)\s*:\s*true\b/i,
    message: "GraphQL introspection/playground appears explicitly enabled."
  }),
  regexMatcher({
    slug: "error-message-leak",
    name: "Raw error returned to client",
    category: "exposure",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:res\.status\s*\(\s*500\s*\)\.(?:send|json)|return\s+NextResponse\.json)\s*\([^)]*(?:err|error|exception)\b/is,
    message: "Raw error object or message appears to be returned to clients."
  }),
  regexMatcher({
    slug: "ai-tool-boundary",
    name: "Privileged AI tool boundary",
    category: "ai-appsec",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:tool|functionTool|defineTool|server\.tool|registerTool)\b[\s\S]{0,800}\b(?:delete|admin|execute|payment|refund|email|database|sql)\b/i,
    message: "AI/tool definition appears to expose a privileged action."
  }),
  regexMatcher({
    slug: "mcp-tool-handler",
    name: "MCP tool handler",
    category: "ai-appsec",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:new\s+McpServer|server\.tool|registerTool|CallToolRequestSchema|ListToolsRequestSchema)\b/i,
    message: "MCP/tool handler should enforce authorization and argument validation inside the handler."
  }),
  regexMatcher({
    slug: "prompt-injection-untrusted-content",
    name: "Untrusted content inserted into model instructions",
    category: "ai-appsec",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:system|developer|instructions|prompt)\b[\s\S]{0,300}\$\{[^}]*\b(?:req|body|query|params|user|content|message)\b/i,
    message: "Untrusted request/user content appears to be interpolated into model instructions."
  }),
  regexMatcher({
    slug: "system-prompt-leak",
    name: "System prompt returned to caller",
    category: "ai-appsec",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:systemPrompt|developerMessage|systemInstruction|instructions)\b[\s\S]{0,500}\b(?:res\.send|res\.json|return\s+NextResponse\.json|return\s+Response\.json)\b/i,
    message: "System/developer prompt content appears close to a response sink."
  }),
  regexMatcher({
    slug: "agent-loop-no-cap",
    name: "Agent loop without obvious cap",
    category: "ai-appsec",
    severity: "medium",
    confidence: "medium",
    noiseTier: "high",
    pattern: /\bwhile\s*\(\s*true\s*\)[\s\S]{0,1000}\b(?:tool|agent|model|chat|completion|invoke)\b/i,
    negativePattern: /\b(?:maxTurns|maxIterations|stepLimit|AbortController|timeout|budget)\b/i,
    message: "Agent/tool loop appears unbounded without an obvious turn, timeout, or budget cap."
  }),
  regexMatcher({
    slug: "github-workflow-token",
    name: "Broad GitHub workflow token permission",
    category: "ci-cd",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.filePath.includes(".github/workflows/"),
    pattern: /permissions:\s*[\s\S]{0,200}(?:contents:\s*write|actions:\s*write|id-token:\s*write)/i,
    message: "Workflow grants powerful token permissions."
  }),
  regexMatcher({
    slug: "github-pull-request-target",
    name: "pull_request_target workflow trigger",
    category: "ci-cd",
    severity: "high",
    confidence: "high",
    noiseTier: "low",
    includeIf: (_text, asset) => asset.filePath.includes(".github/workflows/"),
    pattern: /\bpull_request_target\b/,
    message: "Workflow uses pull_request_target; verify untrusted PR code cannot influence privileged steps."
  }),
  regexMatcher({
    slug: "github-script-injection",
    name: "GitHub script uses pull request context",
    category: "ci-cd",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.filePath.includes(".github/workflows/"),
    pattern: /\bgithub-script\b[\s\S]{0,1000}\$\{\{\s*github\.event\.pull_request\./i,
    message: "github-script step appears to consume pull request context; check for script injection."
  }),
  regexMatcher({
    slug: "github-action-unpinned",
    name: "Unpinned GitHub Action reference",
    category: "ci-cd",
    severity: "medium",
    confidence: "medium",
    noiseTier: "high",
    includeIf: (_text, asset) => asset.filePath.includes(".github/workflows/"),
    pattern: /\buses:\s*[^@\s]+@(?:main|master|latest|v?\d+)\b/i,
    message: "Workflow action reference is not pinned to a commit SHA."
  }),
  regexMatcher({
    slug: "package-install-script",
    name: "Package install lifecycle script",
    category: "supply-chain",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.filePath.endsWith("package.json"),
    pattern: /"(?:preinstall|install|postinstall|prepare)"\s*:/,
    message: "Package install lifecycle script can execute during dependency installation."
  }),
  regexMatcher({
    slug: "insecure-crypto",
    name: "Weak or deprecated cryptography",
    category: "crypto",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\b(?:createHash|crypto\.createHash)\s*\(\s*["'](?:md5|sha1)["']|createCipher\s*\(|DES|RC4/i,
    message: "Weak or deprecated cryptographic primitive appears in source."
  }),
  regexMatcher({
    slug: "weak-random-secret",
    name: "Math.random used for security-sensitive value",
    category: "crypto",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    pattern: /\bMath\.random\s*\(\s*\)[\s\S]{0,160}\b(?:token|secret|password|nonce|session|otp|code)\b/i,
    message: "Math.random appears to contribute to a security-sensitive value."
  }),
  regexMatcher({
    slug: "dockerfile-root-user",
    name: "Dockerfile may run as root",
    category: "container",
    severity: "medium",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.language === "dockerfile",
    pattern: /^FROM\s+\S+/m,
    negativePattern: /^USER\s+(?!root\b)\S+/m,
    message: "Dockerfile has no obvious non-root USER directive."
  }),
  regexMatcher({
    slug: "dockerfile-curl-pipe",
    name: "Dockerfile pipes remote script to shell",
    category: "container",
    severity: "high",
    confidence: "medium",
    noiseTier: "low",
    includeIf: (_text, asset) => asset.language === "dockerfile",
    pattern: /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sh|bash)\b/i,
    message: "Dockerfile pipes a remotely downloaded script into a shell."
  }),
  regexMatcher({
    slug: "terraform-public-ingress",
    name: "Terraform public ingress to sensitive port",
    category: "iac",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.filePath.endsWith(".tf"),
    pattern: /cidr_blocks\s*=\s*\[[^\]]*["']0\.0\.0\.0\/0["'][\s\S]{0,500}from_port\s*=\s*(?:22|3389|3306|5432|6379|9200)|from_port\s*=\s*(?:22|3389|3306|5432|6379|9200)[\s\S]{0,500}cidr_blocks\s*=\s*\[[^\]]*["']0\.0\.0\.0\/0["']/i,
    message: "Terraform security group appears to expose a sensitive port to the public internet."
  }),
  regexMatcher({
    slug: "terraform-iam-wildcard",
    name: "Terraform IAM wildcard permission",
    category: "iac",
    severity: "high",
    confidence: "medium",
    noiseTier: "medium",
    includeIf: (_text, asset) => asset.filePath.endsWith(".tf"),
    pattern: /\b(?:actions|Action|resources|Resource)\s*=\s*\[[^\]]*["']\*["']/,
    message: "Terraform IAM policy appears to grant wildcard action or resource access."
  }),
  regexMatcher({
    slug: "kubernetes-privileged-container",
    name: "Kubernetes privileged container",
    category: "iac",
    severity: "high",
    confidence: "high",
    noiseTier: "low",
    includeIf: (_text, asset) => asset.language === "yaml",
    pattern: /\b(?:privileged\s*:\s*true|hostNetwork\s*:\s*true|hostPID\s*:\s*true)\b/i,
    message: "Kubernetes workload enables privileged or host-level container settings."
  }),
  ...EXPANDED_MATCHERS,
  ...PRODUCT_GRADE_MATCHERS,
  routeMissingAuthMatcher()
]);

function securitySurfaceMatcher(slug: string): MatcherPlugin {
  const category = surfaceCategoryForSlug(slug);
  return regexMatcher({
    slug,
    name: `Security surface: ${slug}`,
    category,
    severity: surfaceSeverityForSlug(slug, category),
    confidence: surfaceConfidenceForSlug(slug, category),
    noiseTier: surfaceNoiseForSlug(slug, category),
    filePatterns: surfaceFilePatternsForSlug(slug),
    examples: [surfaceExampleForSlug(slug)],
    provenance: "security-surface-seed",
    includeIf: (_text, asset) => surfaceAssetGate(slug, asset),
    pattern: surfacePatternForSlug(slug),
    negativePattern: surfaceNegativePatternForSlug(slug),
    message: `Security-surface seed ${slug} found code that deserves review.`
  });
}

function uniqueMatchers(matchers: MatcherPlugin[]): MatcherPlugin[] {
  const bySlug = new Map<string, MatcherPlugin>();
  for (const matcher of matchers) {
    const previous = bySlug.get(matcher.slug);
    if (!previous) {
      bySlug.set(matcher.slug, matcher);
      continue;
    }
    bySlug.set(matcher.slug, {
      ...matcher,
      filePatterns: matcher.filePatterns ?? previous.filePatterns,
      examples: matcher.examples ?? previous.examples,
      provenance: matcher.provenance ?? previous.provenance
    });
  }
  return [...bySlug.values()];
}

function surfaceCategoryForSlug(slug: string): string {
  if (isEntrypointSlug(slug)) return "entrypoint";
  if (slug.includes("secret") || slug.includes("env-exposure") || slug === "process-env-access") return "secrets";
  if (/(sql|nosql|soql|xss|dangerous-html|object-injection|spread-operator|zod|template|xpath)/.test(slug)) return "injection";
  if (/(rce|command|exec|sandbox-runtime|lua-ngx)/.test(slug)) return "rce";
  if (/(auth|jwt|oauth|session|rate-limit|slack-signing|test-header|algorithm-confusion)/.test(slug)) return "auth";
  if (/(ssrf|redirect|url|untrusted-fetch|git-provider)/.test(slug)) return "ssrf";
  if (/(crypto|tls)/.test(slug)) return "crypto";
  if (/(dockerfile|k8s|tf-|iam|terraform)/.test(slug)) return "iac";
  if (/(github|ci|workflow|cron)/.test(slug)) return "ci-cd";
  if (/(agent|mcp|prompt|tool|ai)/.test(slug)) return "ai-security";
  if (/(cache)/.test(slug)) return "cache";
  if (/(android|ios)/.test(slug)) return "mobile";
  if (/(deserialization|unsafe-deserialization)/.test(slug)) return "deserialization";
  if (/(path|fs-write|non-atomic)/.test(slug)) return "filesystem";
  return "security";
}

function surfaceSeverityForSlug(slug: string, category: string): Severity {
  if (category === "entrypoint") return "info";
  if (category === "secrets" || category === "rce" || slug.includes("unsafe-deserialization")) return "critical";
  if (category === "injection" || category === "auth" || category === "ssrf" || category === "iac" || category === "ai-security") return "high";
  return "medium";
}

function surfaceConfidenceForSlug(slug: string, category: string): Confidence {
  if (category === "entrypoint") return "low";
  if (/(secret|private|token|dockerfile-curl-pipe|dockerfile-from-mutable-tag|dockerfile-run-as-root|k8s-secret|tf-iam|cors-wildcard|jwt|slack-signing)/.test(slug)) {
    return "high";
  }
  return "medium";
}

function surfaceNoiseForSlug(slug: string, category: string): "low" | "medium" | "high" {
  if (category === "entrypoint") return "high";
  if (/(secret|dockerfile-curl-pipe|dockerfile-run-as-root|dockerfile-from-mutable-tag|cors-wildcard|jwt|k8s-secret|tf-iam|unsafe-deserialization)/.test(slug)) {
    return "low";
  }
  return category === "ai-security" || category === "cache" || category === "filesystem" ? "medium" : "medium";
}

function surfaceFilePatternsForSlug(slug: string): string[] {
  if (slug.startsWith("js-")) return ["**/*.{ts,tsx,js,jsx,mjs,cjs}"];
  if (slug.startsWith("py-")) return ["**/*.py"];
  if (slug.startsWith("go-")) return ["**/*.go"];
  if (slug.startsWith("rb-")) return ["**/*.rb"];
  if (slug.startsWith("php-")) return ["**/*.php"];
  if (slug.startsWith("rs-")) return ["**/*.rs"];
  if (slug.startsWith("jvm-")) return ["**/*.{java,kt,kts,scala}"];
  if (slug.startsWith("dotnet-")) return ["**/*.cs"];
  if (slug.startsWith("tf-")) return ["**/*.tf"];
  if (slug.startsWith("k8s-")) return ["**/*.{yaml,yml}"];
  if (slug.startsWith("dockerfile-")) return ["**/Dockerfile", "**/*.dockerfile"];
  if (slug.startsWith("lua-")) return ["**/*.lua"];
  if (slug.startsWith("clj-")) return ["**/*.{clj,cljs,cljc}"];
  if (slug.startsWith("ex-")) return ["**/*.{ex,exs}"];
  if (slug.startsWith("erl-")) return ["**/*.erl"];
  if (slug.startsWith("cr-")) return ["**/*.cr"];
  if (slug.startsWith("dart-")) return ["**/*.dart"];
  if (slug.startsWith("swift-")) return ["**/*.swift"];
  if (slug.startsWith("apex-")) return ["**/*.{cls,apex}"];
  return ["**/*"];
}

function surfaceAssetGate(slug: string, asset: FileAsset): boolean {
  const filePath = asset.filePath.toLowerCase();
  if (slug.startsWith("js-")) return ["javascript", "typescript"].includes(asset.language);
  if (slug.startsWith("py-")) return asset.language === "python";
  if (slug.startsWith("go-")) return asset.language === "go";
  if (slug.startsWith("rb-")) return asset.language === "ruby";
  if (slug.startsWith("php-")) return asset.language === "php";
  if (slug.startsWith("rs-")) return asset.language === "rust";
  if (slug.startsWith("jvm-")) return ["java", "kotlin", "scala"].includes(asset.language);
  if (slug.startsWith("dotnet-")) return asset.language === "csharp";
  if (slug.startsWith("tf-")) return asset.language === "terraform";
  if (slug.startsWith("k8s-")) return asset.language === "yaml";
  if (slug.startsWith("dockerfile-")) return asset.language === "dockerfile";
  if (slug.startsWith("lua-")) return asset.language === "lua";
  if (slug.startsWith("clj-")) return asset.language === "clojure";
  if (slug.startsWith("ex-")) return asset.language === "elixir";
  if (slug.startsWith("erl-")) return asset.language === "erlang";
  if (slug.startsWith("cr-")) return asset.language === "crystal";
  if (slug.startsWith("dart-")) return asset.language === "dart";
  if (slug.startsWith("swift-")) return asset.language === "swift";
  if (slug.startsWith("apex-")) return asset.language === "apex";
  if (slug.startsWith("android-")) return filePath.endsWith("androidmanifest.xml");
  if (slug.startsWith("ios-")) return asset.language === "swift" || filePath.endsWith("info.plist");
  if (slug.startsWith("github-")) return filePath.includes(".github/workflows/");
  return true;
}

function surfaceNegativePatternForSlug(slug: string): RegExp | undefined {
  if (/(auth|route|controller|handler|endpoint|resource|public-endpoint|service-entry-point)/.test(slug)) {
    return /\b(?:requireAuth|authorize|authenticate|isAuthenticated|permission|role|middleware|guard|policy|verifyToken|protectedProcedure)\b/i;
  }
  if (/(sql|nosql|soql|xss|dangerous-html|url-regex|redirect|path-traversal)/.test(slug)) {
    return /\b(?:sanitize|escape|allowlist|whitelist|validate|safeParse|parameterized|prepare|bind|DOMPurify)\b/i;
  }
  return undefined;
}

function surfacePatternForSlug(slug: string): RegExp {
  if (slug.includes("loop-budget")) return /\b(?:while\s*\(\s*true\s*\)|for\s*\(\s*;\s*;\s*\)|agentLoop|runAgent)\b/i;
  if (slug.includes("tool") || slug.includes("mcp")) return /\b(?:server\.tool|registerTool|ToolDefinition|tools\s*:\s*\[|functionTool|defineTool)\b/i;
  if (slug.includes("prompt") || slug.includes("rag")) return /\b(?:prompt|messages|system|developer|retrieved|context|chunks)\b[\s\S]{0,320}\b(?:req\.|request\.|userInput|input|body|query|params|innerHTML|dangerouslySetInnerHTML)\b/i;
  if (slug.includes("jwt") || slug.includes("algorithm")) return /\b(?:jwt\.decode|jwt\.verify|algorithms?\s*:\s*\[[^\]]*none|ignoreExpiration\s*:\s*true)\b/i;
  if (slug.includes("android-exported")) return /android:exported\s*=\s*["']true["']/i;
  if (slug.includes("development-bypass")) return /\b(?:bypassAuth|DISABLE_AUTH|SKIP_AUTH|devAuth|if\s*\([^)]*(?:dev|test)[^)]*\)\s*return\s+true)\b/i;
  if (slug.includes("cache")) return /\b(?:cache|redis|memcached)\.(?:get|set|put)\s*\([^)]*(?:req\.|request\.|query|params|body|url)\b/i;
  if (slug.includes("cors")) return /\bAccess-Control-Allow-Origin\b[\s\S]{0,120}\*|origin\s*:\s*["']\*["']/i;
  if (slug.includes("tenant")) return /\b(?:tenantId|orgId|workspaceId|accountId)\b\s*=\s*(?:req\.|request\.|params|query|body)/i;
  if (slug.includes("weak") || slug.includes("crypto")) return /\b(?:md5|sha1|createHash\s*\(\s*["'](?:md5|sha1)|DES|RC4|createCipher\s*\()\b/i;
  if (slug.includes("docker") && slug.includes("curl")) return /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sh|bash)\b/i;
  if (slug.includes("docker") && slug.includes("latest")) return /^FROM\s+\S+:(?:latest|main|master)\b/im;
  if (slug.includes("docker") && slug.includes("root")) return /^FROM\s+\S+/im;
  if (slug.includes("env")) return /\b(?:process\.env|os\.environ|ENV\[|System\.getenv|Environment\.GetEnvironmentVariable)\b/i;
  if (slug.includes("stacktrace") || slug.includes("trace")) return /\b(?:stack|stacktrace|trace|error\.message|exception)\b[\s\S]{0,240}\b(?:res\.|response|log|logger|console)\b/i;
  if (slug.includes("workflow") || slug.includes("github")) return /\b(?:pull_request_target|permissions\s*:\s*write-all|secrets\.|github\.event\.pull_request)\b/i;
  if (slug.includes("command") || slug.includes("rce") || slug.includes("shell")) return /\b(?:exec\.Command|Runtime\.getRuntime\(\)\.exec|child_process|subprocess|system\s*\(|eval\s*\(|exec\s*\()\b/i;
  if (slug.includes("iam")) return /\b(?:Action|actions|Resource|resources)\b\s*[:=]\s*(?:["']\*["']|\[[^\]]*["']\*["'])/i;
  if (slug.includes("secret")) return /\b(?:secretKeyRef|envFrom|kind\s*:\s*Secret|password|secret|token|api[_-]?key|private[_-]?key|credential)\b[\s\S]{0,360}(?:["'][^"']{8,}["']|valueFrom|key)\b/i;
  if (slug.includes("postmessage")) return /\bpostMessage\b|\baddEventListener\s*\(\s*["']message["']/i;
  if (slug.includes("redirect")) return /\b(?:redirect|Location|sendRedirect|RedirectResponse)\s*\([^)]*(?:req\.|request\.|params|query|body|url|next)\b/i;
  if (slug.includes("path") || slug.includes("filesystem")) return /\b(?:readFile|createReadStream|sendFile|download|open|writeFile|createWriteStream|rename|copyFile|move)\s*\([^)]*(?:req\.|request\.|params|query|body|filename|path)\b/i;
  if (slug.includes("deserialization")) return /\b(?:pickle\.loads?|unserialize|ObjectInputStream|BinaryFormatter|Marshal\.load|yaml\.load)\s*\(/i;
  if (slug.includes("sql") || slug.includes("soql") || slug.includes("warehouse")) return /\b(?:query|execute|raw|select|SOQL|BigQuery|Snowflake)\s*\([^)]*(?:\+|\$\{|format\s*\(|req\.|request\.|params|query|body)|["'`](?:select|update|delete|insert)[^"'`]*(?:\+|\$\{)/i;
  if (slug.includes("nosql")) return /\.(?:find|findOne|update|deleteOne|deleteMany)\s*\([^)]*(?:req\.body|request\.json|body)/is;
  if (slug.includes("ssrf") || slug.includes("fetch")) return /\b(?:fetch|axios|requests\.get|http\.Get|client\.Get|open-uri|Net::HTTP|curl)\s*\([^)]*(?:req\.|request\.|params|query|body|url)\b/i;
  if (slug.includes("terraform")) return /\b(?:resource|data)\s+"(?:aws_|google_|azurerm_)[^"]+"[\s\S]{0,700}\b(?:0\.0\.0\.0\/0|\*|unencrypted|public|secret|module|source)\b/i;
  if (slug.includes("kubernetes")) return /\b(?:privileged|hostPath|runAsUser\s*:\s*0|secretKeyRef|hostNetwork|allowPrivilegeEscalation|LoadBalancer|readOnlyRootFilesystem)\b/i;
  if (slug.includes("electron")) return /\b(?:nodeIntegration\s*:\s*true|contextIsolation\s*:\s*false)\b/i;
  if (slug.includes("mobile") || slug.includes("ios") || slug.includes("android")) return /\b(?:usesCleartextTraffic|allowBackup|NSAllowsArbitraryLoads|CFBundleURLSchemes|javaScriptEnabled|AsyncStorage)\b/i;
  if (slug.includes("template") || slug.includes("html")) return /\b(?:innerHTML|dangerouslySetInnerHTML|v-html|bypassSecurityTrustHtml|rawHtml|template\.render)\b/i;
  if (slug === "agent-loop-no-cap") return /\b(?:while\s*\(\s*true\s*\)|for\s*\(\s*;\s*;\s*\)|agentLoop|runAgent)\b/i;
  if (slug === "agent-tool-definition" || slug === "mcp-tool-handler") return /\b(?:server\.tool|registerTool|ToolDefinition|tools\s*:\s*\[)\b/i;
  if (slug === "agentic-untrusted-prompt-input") return /\b(?:prompt|messages|system|developer)\b[\s\S]{0,320}\b(?:req\.|request\.|userInput|input|body|query|params)\b/i;
  if (slug === "algorithm-confusion" || slug === "jwt-handling") return /\b(?:jwt\.decode|jwt\.verify|algorithms?\s*:\s*\[[^\]]*none|ignoreExpiration\s*:\s*true)\b/i;
  if (slug === "android-manifest-export") return /android:exported\s*=\s*["']true["']/i;
  if (slug === "auth-bypass" || slug === "dev-auth-bypass") return /\b(?:bypassAuth|DISABLE_AUTH|SKIP_AUTH|devAuth|if\s*\([^)]*(?:dev|test)[^)]*\)\s*return\s+true)\b/i;
  if (slug === "cache-key-poisoning" || slug === "cache-key-scope") return /\b(?:cache|redis|memcached)\.(?:get|set|put)\s*\([^)]*(?:req\.|request\.|query|params|body|url)\b/i;
  if (slug === "cors-wildcard") return /\bAccess-Control-Allow-Origin\b[\s\S]{0,120}\*|origin\s*:\s*["']\*["']/i;
  if (slug === "cron-secret-check") return /\b(?:cron|schedule|setInterval)\b[\s\S]{0,320}\b(?:secret|token|password|apiKey)\b/i;
  if (slug === "cross-tenant-id") return /\b(?:tenantId|orgId|workspaceId|accountId)\b\s*=\s*(?:req\.|request\.|params|query|body)/i;
  if (slug === "crypto-usage" || slug === "insecure-crypto") return /\b(?:md5|sha1|createHash\s*\(\s*["'](?:md5|sha1)|DES|RC4|createCipher\s*\()\b/i;
  if (slug === "dockerfile-curl-pipe-unverified") return /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sh|bash)\b/i;
  if (slug === "dockerfile-from-mutable-tag") return /^FROM\s+\S+:(?:latest|main|master)\b/im;
  if (slug === "dockerfile-run-as-root") return /^FROM\s+\S+/im;
  if (slug === "env-exposure" || slug === "process-env-access") return /\b(?:process\.env|os\.environ|ENV\[|System\.getenv|Environment\.GetEnvironmentVariable)\b/i;
  if (slug === "env-var-as-bool") return /\b(?:Boolean\s*\(\s*process\.env|!!\s*process\.env|process\.env\.\w+\s*\?\s*true\s*:\s*false)\b/i;
  if (slug === "error-message-leak" || slug === "sensitive-data-in-traces") return /\b(?:stack|stacktrace|trace|error\.message|exception)\b[\s\S]{0,240}\b(?:res\.|response|log|logger|console)\b/i;
  if (slug === "event-handler-mismatch") return /\b(?:webhook|event|callback)\b[\s\S]{0,320}\b(?:handler|on|subscribe)\b/i;
  if (slug === "expensive-api-abuse") return /\b(?:for\s*\(|while\s*\(|Promise\.all|map\s*\()\b[\s\S]{0,320}\b(?:fetch|axios|query|findMany|scan)\b/i;
  if (slug === "fs-write-symlink-boundary") return /\b(?:writeFile|createWriteStream|rename|copyFile|move)\s*\([^)]*(?:req\.|request\.|params|query|body|path)\b/i;
  if (slug === "github-workflow-security") return /\b(?:pull_request_target|permissions\s*:\s*write-all|secrets\.|github\.event\.pull_request)\b/i;
  if (slug === "git-provider-url-injection") return /\b(?:clone|checkout|git)\b[\s\S]{0,220}\b(?:req\.|request\.|repoUrl|repositoryUrl|gitUrl)\b/i;
  if (slug === "go-command-injection" || slug === "rce") return /\b(?:exec\.Command|Runtime\.getRuntime\(\)\.exec|child_process|subprocess|system\s*\(|eval\s*\()\b/i;
  if (slug === "go-embed-asset") return /^\/\/go:embed\s+/m;
  if (slug === "iam-permissions" || slug === "tf-iam-wildcard") return /\b(?:Action|actions|Resource|resources)\b\s*[:=]\s*(?:["']\*["']|\[[^\]]*["']\*["'])/i;
  if (slug === "ios-url-scheme") return /\b(?:CFBundleURLSchemes|openURL|canOpenURL)\b/i;
  if (slug === "k8s-secret-reference" || slug === "k8s-secrets-init-container") return /\b(?:secretKeyRef|envFrom|kind\s*:\s*Secret|initContainers)\b[\s\S]{0,360}\b(?:secret|password|token|key)\b/i;
  if (slug.startsWith("lua-")) return /\b(?:ngx\.exec|ngx\.redirect|ngx\.re|shared\.dict|md5|sha1|string\.format)\b/i;
  if (slug === "missing-await") return /\b(?:fetch|axios|save|delete|query|update|insert)\s*\([^)]*\)\s*;/i;
  if (slug === "non-atomic-operation" || slug === "non-atomic-read-delete") return /\b(?:exists|find|read|stat)\b[\s\S]{0,320}\b(?:delete|remove|write|update|insert)\b/i;
  if (slug === "oauth-flow") return /\b(?:authorization_code|redirect_uri|oauth|callback)\b[\s\S]{0,420}\b(?:code|token)\b/i;
  if (slug === "object-injection" || slug === "spread-operator-injection" || slug === "zod-passthrough-mass-assignment") return /\b(?:\.\.\.\s*(?:req|request)\.(?:body|query)|Object\.assign\s*\([^)]*(?:req|request)\.(?:body|query)|\.passthrough\s*\()\b/i;
  if (slug === "open-redirect" || slug === "unsafe-redirect" || slug === "untrusted-redirect-following") return /\b(?:redirect|Location|sendRedirect|RedirectResponse)\s*\([^)]*(?:req\.|request\.|params|query|body|url|next)\b/i;
  if (slug === "path-traversal") return /\b(?:readFile|createReadStream|sendFile|download|open)\s*\([^)]*(?:req\.|request\.|params|query|body|filename|path)\b/i;
  if (slug === "postmessage-origin") return /\bpostMessage\b|\baddEventListener\s*\(\s*["']message["']/i;
  if (slug === "prompt-leaks-system-prompt") return /\b(?:systemPrompt|developerPrompt|SYSTEM_PROMPT|prompt)\b[\s\S]{0,240}\b(?:console\.log|res\.|return|debug|trace)\b/i;
  if (slug === "rate-limit-bypass") return /\b(?:rateLimit|limiter|throttle)\b[\s\S]{0,240}\b(?:skip|disable|false|bypass)\b/i;
  if (slug === "sandbox-runtime-script") return /\b(?:vm2|isolated-vm|Docker|sandbox|runInNewContext|execFile)\b[\s\S]{0,240}\b(?:script|code|command)\b/i;
  if (slug === "secret-env-var" || slug === "secret-in-fallback" || slug === "secret-in-log" || slug === "secrets-exposure" || slug === "secrets-plaintext-exposure") {
    return /\b(?:password|secret|token|api[_-]?key|private[_-]?key|credential)\b\s*[:=]\s*["'][^"']{8,}["']|\b(?:console\.log|logger|trace)\s*\([^)]*(?:password|secret|token|apiKey)/i;
  }
  if (slug === "security-behind-flag" || slug === "test-header-bypass") return /\b(?:DISABLE_|SKIP_|BYPASS_|X-Test|X-Debug|test-header)\w*\b/i;
  if (slug === "session-cookie-config") return /\b(?:secure|httpOnly|sameSite)\s*:\s*false\b|SameSite=None/i;
  if (slug === "slack-signing-verification") return /\b(?:x-slack-signature|X-Slack-Signature|slack)\b/i;
  if (slug === "snowflake-bigquery-sql" || slug.includes("sql") || slug === "soql-injection") return /\b(?:query|execute|raw|select|SOQL|BigQuery|Snowflake)\s*\([^)]*(?:\+|\$\{|format\s*\(|req\.|request\.|params|query|body)|["'`](?:select|update|delete|insert)[^"'`]*(?:\+|\$\{)/i;
  if (slug === "ssrf" || slug === "go-ssrf" || slug === "url-regex-validation") return /\b(?:fetch|axios|requests\.get|http\.Get|client\.Get|open-uri|Net::HTTP|curl)\s*\([^)]*(?:req\.|request\.|params|query|body|url)\b/i;
  if (slug.startsWith("tf-")) return /\b(?:resource|data)\s+"(?:aws_|google_|azurerm_)[^"]+"[\s\S]{0,700}\b(?:0\.0\.0\.0\/0|\*|unencrypted|public|secret|module|source)\b/i;
  if (slug === "trpc-public-procedure") return /\bpublicProcedure\b/i;
  if (slug === "unix-socket-listener") return /\b(?:listen|bind)\s*\([^)]*(?:\/tmp\/|unix:|\.sock)\b/i;
  if (slug === "unsafe-deserialization") return /\b(?:pickle\.loads?|unserialize|ObjectInputStream|BinaryFormatter|Marshal\.load|yaml\.load)\s*\(/i;
  if (slug === "unverified-lookup") return /\b(?:findUnique|findOne|findById|FirstOrDefault)\s*\([^)]*(?:req\.|request\.|params|query|body)\b/i;
  if (slug === "webhook-handler") return /\b(?:webhook|stripe|github|slack|signature)\b[\s\S]{0,360}\b(?:handler|post|route|endpoint)\b/i;
  if (slug === "xss" || slug === "dangerous-html" || slug === "js-react-unsafe-json-in-html") return /\b(?:innerHTML|dangerouslySetInnerHTML|v-html|bypassSecurityTrustHtml|rawHtml)\b/i;
  if (isEntrypointSlug(slug)) return entrypointPatternForSlug(slug);
  return fallbackPatternForSlug(slug);
}

function entrypointPatternForSlug(slug: string): RegExp {
  if (slug.includes("express")) return /\b(?:app|router)\.(?:get|post|put|patch|delete|all|use)\s*\(|express\.Router\s*\(/i;
  if (slug.includes("fastify")) return /\bfastify\.(?:get|post|put|patch|delete|route)\s*\(/i;
  if (slug.includes("hono")) return /\bnew\s+Hono\b|\.route\s*\(|\bapp\.(?:get|post|put|patch|delete)\s*\(/i;
  if (slug.includes("koa")) return /\bnew\s+Router\b|router\.(?:get|post|put|patch|delete)\s*\(|ctx\./i;
  if (slug.includes("hapi")) return /\bserver\.route\s*\(|method\s*:\s*["'](?:GET|POST|PUT|PATCH|DELETE)/i;
  if (slug.includes("nestjs")) return /@(?:Controller|Get|Post|Put|Patch|Delete)\b/i;
  if (slug.includes("nextjs")) return /\bexport\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)|\buse\s+server\b|middleware\s*\(/i;
  if (slug.includes("remix")) return /\bexport\s+(?:async\s+)?(?:function\s+)?(?:loader|action)\b/i;
  if (slug.includes("sveltekit")) return /\bexport\s+(?:const|async\s+function)\s+(?:GET|POST|PUT|PATCH|DELETE|load|actions)\b/i;
  if (slug.includes("nuxt")) return /\bdefineEventHandler\s*\(|eventHandler\s*\(/i;
  if (slug.includes("astro")) return /\bexport\s+(?:async\s+)?(?:function\s+)?(?:GET|POST|PUT|PATCH|DELETE)\b/i;
  if (slug.includes("workers")) return /\bfetch\s*\(\s*request|addEventListener\s*\(\s*["']fetch["']/i;
  if (slug.includes("deno")) return /\bDeno\.serve\s*\(|serve\s*\(\s*(?:req|request)/i;
  if (slug.includes("bun")) return /\bBun\.serve\s*\(/i;
  if (slug.includes("go-") || slug.includes("go-") || slug.includes("gin") || slug.includes("fiber") || slug.includes("echo") || slug.includes("chi") || slug.includes("gorilla") || slug.includes("buffalo") || slug.includes("cobra")) return /\b(?:http\.HandleFunc|gin\.Default|gin\.New|fiber\.New|echo\.New|chi\.NewRouter|mux\.NewRouter|buffalo\.New|cobra\.Command)\b/i;
  if (slug.includes("python")) return /\b(?:FastAPI|Flask|Django|aiohttp|Sanic|Falcon|Bottle|Starlette|Tornado|Celery|DAG)\b|@\w+\.(?:get|post|route)\s*\(/i;
  if (slug.includes("ruby")) return /\b(?:Rails::Application|class\s+\w+Controller|Sinatra::Base|Grape::API|Roda|Hanami::Action|get\s+["']\/|post\s+["']\/)/i;
  if (slug.includes("php")) return /\b(?:Route::|Controller|WP_REST|register_rest_route|Symfony|Slim|Laravel|Cake|CodeIgniter|Yii|Magento|Drupal)\b/i;
  if (slug.includes("jvm")) return /@(?:RestController|Controller|RequestMapping|Path|GET|POST)|\b(?:Ktor|Micronaut|Javalin|routes?)\b/i;
  if (slug.includes("dotnet")) return /\b(?:ControllerBase|ApiController|MapGet|MapPost|HttpTrigger|RazorPage|PageModel)\b/i;
  if (slug.includes("rust")) return /\b(?:actix_web|axum|Router::new|rocket::|poem::|warp::|tide::|tonic::|lambda_runtime)\b/i;
  if (slug.includes("lua")) return /\bngx\.(?:location|req|say|exec|redirect)\b/i;
  if (slug.includes("clojure")) return /\b(?:defroutes|GET\s+["']\/|POST\s+["']\/|ring\.util\.response)\b/i;
  if (slug.includes("elixir")) return /\b(?:use\s+\w+Web,\s*:controller|Phoenix\.Controller|plug\s+:|scope\s+["']\/)\b/i;
  if (slug.includes("erlang")) return /\b(?:cowboy_router|cowboy_req|init\s*\(\s*Req)\b/i;
  if (slug.includes("crystal")) return /\b(?:Kemal|HTTP::Server|get\s+["']\/|post\s+["']\/)\b/i;
  if (slug.includes("dart")) return /\b(?:shelf|Router\(\)|handler\s*\(|Response\.ok)\b/i;
  if (slug.includes("swift")) return /\b(?:Vapor|routes|app\.(?:get|post|put|delete)|Request)\b/i;
  if (slug.includes("apex")) return /@RestResource|@Http(?:Get|Post|Put|Patch|Delete)/i;
  if (slug.includes("azure")) return /\b(?:AzureFunction|HttpTrigger|app\.http|context\.req)\b/i;
  if (slug.includes("gcp")) return /\b(?:functions\.https|onRequest|CloudFunctions|http\s*\(request)/i;
  if (slug.includes("lambda")) return /\b(?:exports\.handler|lambda_handler|APIGatewayProxy|aws_lambda)\b/i;
  return /\b(?:route|router|controller|handler|endpoint|request|response)\b/i;
}

function fallbackPatternForSlug(slug: string): RegExp {
  const tokens = slug
    .split("-")
    .filter((token) => token.length > 3 && !["handler", "route", "matcher"].includes(token))
    .slice(0, 3)
    .map(escapeRegExp);
  if (tokens.length === 0) return /\b(?:security|auth|token|request|handler)\b/i;
  return new RegExp(tokens.join("[\\s\\S]{0,120}"), "i");
}

function surfaceExampleForSlug(slug: string): string {
  if (slug.startsWith("js-express")) return `app.get("/users", (req, res) => res.json({ ok: true }));`;
  if (slug.startsWith("go-gin")) return `r := gin.Default(); r.GET("/users", handler)`;
  if (slug.startsWith("py-fastapi")) return `app = FastAPI()\n@app.get("/users")\ndef users(): return []`;
  if (slug.startsWith("rb-rails")) return `class UsersController < ApplicationController\n  def index; end\nend`;
  if (slug.startsWith("rs-axum")) return `Router::new().route("/users", get(handler));`;
  if (slug.startsWith("jvm-spring")) return `@RestController class Users { @GetMapping("/users") fun users() {} }`;
  if (slug.startsWith("dotnet")) return `[ApiController] public class UsersController : ControllerBase { [HttpGet] public IActionResult Get() => Ok(); }`;
  if (slug.startsWith("tf-")) return `resource "aws_security_group" "x" { ingress { cidr_blocks = ["0.0.0.0/0"] } }`;
  if (slug.startsWith("k8s-")) return `env:\n- name: TOKEN\n  valueFrom:\n    secretKeyRef:\n      name: api\n      key: token`;
  if (slug.startsWith("dockerfile-")) return `FROM node:latest\nRUN curl https://example.test/install.sh | sh`;
  if (slug.includes("sql")) return `db.query("select * from users where id = " + req.query.id);`;
  if (slug.includes("secret")) return `const apiKey = "super-secret-token-value";`;
  if (slug.includes("redirect")) return `res.redirect(req.query.next);`;
  if (slug.includes("ssrf")) return `fetch(req.query.url);`;
  if (slug.includes("xss") || slug.includes("dangerous-html")) return `<div dangerouslySetInnerHTML={{__html: req.query.html}} />`;
  if (isEntrypointSlug(slug)) return `router.get("/example", handler);`;
  return `// ${slug}\nconst request = getUserInput();`;
}

function isEntrypointSlug(slug: string): boolean {
  return /(route|controller|handler|endpoint|resource|function|surface|entry-point|processor|middleware|server-action|grpc|rpc|serve|fetch|cobra-command|airflow-dag|celery-task|socketio|bullmq|workers|lambda-runtime|public-endpoint|service-entry-point|streaming-endpoint|minimal-api|razor-pages|aspnet|cloud-function)/.test(slug);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function regexMatcher(params: MatcherMetadata & {
  pattern: RegExp;
  negativePattern?: RegExp;
  includeIf?: (text: string, asset: FileAsset) => boolean;
  message: string;
}): MatcherPlugin {
  return {
    slug: params.slug,
    name: params.name,
    category: params.category,
    severity: params.severity,
    confidence: params.confidence,
    noiseTier: params.noiseTier,
    frameworks: params.frameworks,
    filePatterns: params.filePatterns,
    examples: params.examples,
    provenance: params.provenance,
    async run(ctx: MatcherContext): Promise<Signal[]> {
      const signals: Signal[] = [];
      for (const asset of ctx.files()) {
        const text = ctx.readFile(asset.filePath);
        if (params.includeIf && !params.includeIf(text, asset)) continue;
        if (!params.pattern.test(text)) continue;
        if (params.negativePattern && params.negativePattern.test(text)) continue;
        const match = firstMatch(text, params.pattern);
        signals.push(ctx.signal({
          asset,
          slug: params.slug,
          confidence: params.confidence,
          weight: params.confidence === "high" ? 1 : 0.7,
          lineNumbers: match ? [lineNumberForIndex(text, match.index)] : [],
          snippet: match?.text,
          message: params.message,
          raw: { slug: params.slug, category: params.category, severity: params.severity, matcher: params.name }
        }));
      }
      return signals;
    }
  };
}

export function routeMissingAuthMatcher(): MatcherPlugin {
  return {
    slug: "missing-auth",
    name: "Route handler without local auth signal",
    category: "auth",
    severity: "high",
    confidence: "medium",
    noiseTier: "low",
    async run(ctx: MatcherContext): Promise<Signal[]> {
      const signals: Signal[] = [];
      for (const asset of ctx.files({ languages: ["javascript", "typescript", "python"] })) {
        const text = ctx.readFile(asset.filePath);
        if (!looksLikeRoute(text, asset.filePath)) continue;
        if (hasAuthSignal(text)) continue;
        signals.push(ctx.signal({
          asset,
          slug: "missing-auth",
          confidence: "medium",
          weight: 0.8,
          lineNumbers: routeLineNumbers(text),
          snippet: firstRouteSnippet(text),
          message: "Route-like handler has no obvious local authentication or authorization check.",
          raw: { slug: "missing-auth", category: "auth", severity: "high", matcher: "Route handler without local auth signal" }
        }));
      }
      return signals;
    }
  };
}

export function noiseTiersForProfile(profile: MatcherProfile = "strict"): Array<"low" | "medium" | "high"> {
  if (profile === "strict") return ["low"];
  if (profile === "balanced") return ["low", "medium"];
  return ["low", "medium", "high"];
}

export function signalMetadataForSlug(slug: string): Pick<MatcherMetadata, "category" | "severity" | "confidence" | "name"> {
  const matcher = BUILTIN_MATCHERS.find((item) => item.slug === slug);
  return {
    category: matcher?.category ?? "unknown",
    severity: matcher?.severity ?? "medium",
    confidence: matcher?.confidence ?? "medium",
    name: matcher?.name ?? slug
  };
}

function looksLikeRoute(text: string, filePath: string): boolean {
  const normalized = normalizePath(filePath);
  return /(?:app|router)\.(?:get|post|put|patch|delete)\s*\(/.test(text) ||
    /export\s+async\s+function\s+(?:GET|POST|PUT|PATCH|DELETE)\s*\(/.test(text) ||
    /@(app|router)\.(?:get|post|put|patch|delete)\s*\(/.test(text) ||
    normalized.includes("/api/");
}

function hasAuthSignal(text: string): boolean {
  return /\b(?:requireAuth|requireUser|requireAdmin|authorize|isAuthenticated|currentUser|getServerSession|Depends|permission|role|session|jwt|verifyToken)\b/i.test(text);
}

function routeLineNumbers(text: string): number[] {
  const lines: number[] = [];
  const patterns = [
    /app\.(?:get|post|put|patch|delete)\s*\(/g,
    /router\.(?:get|post|put|patch|delete)\s*\(/g,
    /export\s+async\s+function\s+(?:GET|POST|PUT|PATCH|DELETE)\s*\(/g
  ];
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) lines.push(lineNumberForIndex(text, match.index ?? 0));
  }
  return lines.length ? lines : [1];
}

function firstRouteSnippet(text: string): string {
  const lines = text.split(/\r?\n/);
  const lineNo = routeLineNumbers(text)[0] ?? 1;
  return lines.slice(Math.max(0, lineNo - 2), Math.min(lines.length, lineNo + 6)).join("\n");
}

function firstMatch(text: string, pattern: RegExp): { index: number; text: string } | undefined {
  const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
  const clone = new RegExp(pattern.source, flags);
  const match = clone.exec(text);
  if (!match) return undefined;
  return { index: match.index, text: match[0].slice(0, 600) };
}

function lineNumberForIndex(text: string, index: number): number {
  return text.slice(0, index).split(/\r?\n/).length;
}
